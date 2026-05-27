function parseClientPrincipal(request) {
  const encoded = request.headers.get('x-ms-client-principal');
  if (!encoded) return null;

  try {
    const decoded = Buffer.from(encoded, 'base64').toString('utf8');
    return JSON.parse(decoded);
  } catch (error) {
    return null;
  }
}

function getUserEmail(request) {
  const principal = parseClientPrincipal(request);
  if (!principal) return '';

  const claims = principal.claims || [];
  const emailClaim = claims.find((claim) =>
    ['emails', 'preferred_username', 'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress']
      .includes(claim.typ)
  );

  return String(emailClaim?.val || principal.userDetails || '').toLowerCase();
}

function getAdminEmails() {
  return String(process.env.ADMIN_EMAILS || '')
    .split(',')
    .map((email) => email.trim().toLowerCase())
    .filter(Boolean);
}

function requireAdmin(request) {
  const email = getUserEmail(request);
  const admins = getAdminEmails();

  if (!email || !admins.includes(email)) {
    return {
      ok: false,
      response: {
        status: 403,
        jsonBody: {
          ok: false,
          message: 'Access denied. Admin authorization required.'
        }
      }
    };
  }

  return { ok: true, email };
}

module.exports = {
  parseClientPrincipal,
  getUserEmail,
  requireAdmin
};
