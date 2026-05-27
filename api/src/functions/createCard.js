const { app } = require('@azure/functions');
const { encryptText, keyedHash, maskPhone } = require('../lib/crypto');
const { getCardByPhoneHash, upsertCard } = require('../lib/storage');

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

app.http('createCard', {
  methods: ['POST'],
  authLevel: 'anonymous',
  route: 'createCard',
  handler: async (request, context) => {
    try {
      const body = await request.json().catch(() => ({}));

      // Honeypot: real users will never fill this hidden field.
      if (body.companyWebsite) {
        return { status: 400, jsonBody: { ok: false, message: 'Invalid request.' } };
      }

      const name = cleanName(body.name);
      const phone = cleanPhone(body.phone);
      const consent = body.consent === true;
      const source = String(body.source || 'public-form').slice(0, 40);

      if (!name) {
        return { status: 400, jsonBody: { ok: false, message: 'Name is required.' } };
      }

      if (!/^[0-9]{10}$/.test(phone)) {
        return { status: 400, jsonBody: { ok: false, message: 'Enter a valid 10-digit WhatsApp number.' } };
      }

      if (!consent) {
        return { status: 400, jsonBody: { ok: false, message: 'Consent is required to generate the card.' } };
      }

      const phoneHash = keyedHash(phone);
      const existing = await getCardByPhoneHash(phoneHash);

      if (existing) {
        return {
          status: 200,
          jsonBody: {
            ok: true,
            reused: true,
            uniqueId: existing.uniqueId,
            maskedPhone: existing.maskedPhone,
            message: 'Existing card reused for this number.'
          }
        };
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

      return {
        status: 201,
        jsonBody: {
          ok: true,
          reused: false,
          uniqueId,
          maskedPhone: maskPhone(phone),
          message: 'Card created successfully.'
        }
      };
    } catch (error) {
      context.error(error);
      return {
        status: 500,
        jsonBody: {
          ok: false,
          message: 'Card generation failed. Please contact the admin.'
        }
      };
    }
  }
});
