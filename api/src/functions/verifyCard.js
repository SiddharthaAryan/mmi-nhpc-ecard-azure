const { app } = require('@azure/functions');
const { getCardById } = require('../lib/storage');

const corsHeaders = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type'
};

function json(status, body) {
  return { status, headers: corsHeaders, jsonBody: body };
}

app.http('verifyCard', {
  methods: ['GET', 'OPTIONS'],
  authLevel: 'anonymous',
  route: 'verifyCard',
  handler: async (request, context) => {
    if (request.method === 'OPTIONS') {
      return { status: 204, headers: corsHeaders };
    }

    try {
      const id = String(request.query.get('id') || '').trim().slice(0, 80);

      if (!id) {
        return json(400, {
          ok: false,
          valid: false,
          message: 'No card ID found.'
        });
      }

      const card = await getCardById(id);

      if (!card || card.status !== 'active') {
        return json(404, {
          ok: true,
          valid: false,
          cardId: id,
          message: 'This card ID was not found or is inactive.'
        });
      }

      return json(200, {
        ok: true,
        valid: true,
        cardId: card.uniqueId,
        status: 'Active',
        issuedOn: card.createdAt,
        maskedPhone: card.maskedPhone || '',
        message: 'Valid MMI Narayana Health Family Privilege Card.'
      });
    } catch (error) {
      context.error(error);
      return json(500, {
        ok: false,
        valid: false,
        message: 'Verification failed. Please try again later.'
      });
    }
  }
});
