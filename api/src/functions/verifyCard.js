const { app } = require('@azure/functions');
const { getCardById } = require('../lib/storage');

app.http('verifyCard', {
  methods: ['GET'],
  authLevel: 'anonymous',
  route: 'verifyCard',
  handler: async (request, context) => {
    try {
      const id = String(request.query.get('id') || '').trim().slice(0, 80);

      if (!id) {
        return {
          status: 400,
          jsonBody: {
            ok: false,
            valid: false,
            message: 'No card ID found.'
          }
        };
      }

      const card = await getCardById(id);

      if (!card || card.status !== 'active') {
        return {
          status: 404,
          jsonBody: {
            ok: true,
            valid: false,
            cardId: id,
            message: 'This card ID was not found or is inactive.'
          }
        };
      }

      return {
        status: 200,
        jsonBody: {
          ok: true,
          valid: true,
          cardId: card.uniqueId,
          status: 'Active',
          issuedOn: card.createdAt,
          maskedPhone: card.maskedPhone || '',
          message: 'Valid MMI Narayana Health Family Privilege Card.'
        }
      };
    } catch (error) {
      context.error(error);
      return {
        status: 500,
        jsonBody: {
          ok: false,
          valid: false,
          message: 'Verification failed. Please try again later.'
        }
      };
    }
  }
});
