const { app } = require('@azure/functions');
const { encryptText, decryptText, keyedHash, maskPhone } = require('../lib/crypto');
const { getCardByPhoneHash, upsertCard, listCards } = require('../lib/storage');

const corsHeaders = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'POST, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type',
  'Cache-Control': 'no-store'
};

function json(status, body) {
  return { status, headers: corsHeaders, jsonBody: body };
}

function html(status, body) {
  return {
    status,
    headers: {
      'Content-Type': 'text/html; charset=utf-8',
      'Cache-Control': 'no-store'
    },
    body
  };
}

function csv(status, body, filename) {
  return {
    status,
    headers: {
      'Content-Type': 'text/csv; charset=utf-8',
      'Content-Disposition': `attachment; filename="${filename}"`,
      'Cache-Control': 'no-store'
    },
    body
  };
}

function cleanPhone(phone) {
  return String(phone || '').replace(/\D/g, '');
}

function cleanName(name) {
  return String(name || '').replace(/[<>]/g, '').replace(/\s+/g, ' ').trim().slice(0, 80);
}

function makeCardIdFromPhoneHash(phoneHash) {
  // Deterministic ID: same phone number will always map to the same card ID.
  // This prevents duplicate IDs for the same number even under repeated submissions.
  const prefix = process.env.CARD_PREFIX || 'NHPC-RPR';
  const compact = String(phoneHash || '').replace(/[^a-zA-Z0-9]/g, '').toUpperCase().slice(0, 8);
  return `${prefix}-${compact}`;
}

function safeDecrypt(value) {
  try {
    return decryptText(value);
  } catch (_) {
    return '';
  }
}

function csvCell(value) {
  return `"${String(value ?? '').replace(/"/g, '""')}"`;
}

function getLoginUrl(request) {
  const currentUrl = new URL(request.url);
  return `/.auth/login/aad?post_login_redirect_uri=${encodeURIComponent(currentUrl.pathname)}`;
}

function getClientPrincipal(request) {
  const encoded = request.headers.get('x-ms-client-principal');
  if (encoded) {
    try {
      const decoded = Buffer.from(encoded, 'base64').toString('utf8');
      const principal = JSON.parse(decoded);
      const emailClaim = (principal.claims || []).find((claim) =>
        ['preferred_username', 'email', 'upn'].some((key) => String(claim.typ || '').toLowerCase().includes(key))
      );
      return {
        name: principal.userDetails || principal.userId || '',
        email: String((emailClaim && emailClaim.val) || principal.userDetails || '').toLowerCase()
      };
    } catch (_) {}
  }

  const fallbackEmail = String(
    request.headers.get('x-ms-client-principal-name') ||
    request.headers.get('x-ms-client-principal-id') ||
    ''
  ).toLowerCase();

  return fallbackEmail ? { name: fallbackEmail, email: fallbackEmail } : null;
}

function getAllowedEmails() {
  return String(process.env.ADMIN_EMAILS || '')
    .split(',')
    .map((email) => email.trim().toLowerCase())
    .filter(Boolean);
}

function isAllowedAdmin(email) {
  const allowed = getAllowedEmails();
  return allowed.length > 0 && allowed.includes(String(email || '').toLowerCase());
}

function redirectToLogin(request) {
  return {
    status: 302,
    headers: {
      Location: getLoginUrl(request),
      'Cache-Control': 'no-store'
    }
  };
}

async function getAdminRows(limit = 5000) {
  const cards = await listCards(limit);
  const seen = new Set();
  const rows = [];

  for (const card of cards) {
    const uniqueKey = card.phoneHash || card.uniqueId || card.rowKey;
    if (seen.has(uniqueKey)) continue;
    seen.add(uniqueKey);

    rows.push({
      uniqueId: card.uniqueId || card.rowKey || '',
      name: safeDecrypt(card.encryptedName),
      phone: safeDecrypt(card.encryptedPhone),
      maskedPhone: card.maskedPhone || '',
      status: card.status || '',
      source: card.source || '',
      consentGiven: card.consentGiven === true,
      createdAt: card.createdAt || '',
      updatedAt: card.updatedAt || ''
    });
  }

  return rows;
}

async function handleAdminSummary(body) {
  const expected = process.env.ADMIN_ACCESS_KEY;
  const provided = String(body.adminKey || '').trim();
  if (!expected || provided !== expected) {
    return json(401, { ok: false, message: 'Unauthorized admin access.' });
  }

  const limit = Math.min(Math.max(Number(body.limit || 5000), 1), 5000);
  const rows = await getAdminRows(limit);
  return json(200, { ok: true, count: rows.length, rows });
}

function renderAdminPage(rows, user) {
  const safeRows = JSON.stringify(rows).replace(/</g, '\\u003c');
  const total = rows.length;
  const active = rows.filter((row) => row.status === 'active').length;
  const today = rows.filter((row) => {
    if (!row.createdAt) return false;
    return new Date(row.createdAt).toDateString() === new Date().toDateString();
  }).length;

  return `<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0"><title>NHPC Admin Dashboard</title><style>
*{box-sizing:border-box}body{margin:0;font-family:Arial,system-ui,sans-serif;background:#07152f;color:#fff;padding:24px}.wrap{max-width:1200px;margin:auto}.top{display:flex;justify-content:space-between;align-items:center;gap:16px;margin-bottom:20px}.user{font-size:13px;color:#cfe3ff}.grid{display:grid;grid-template-columns:repeat(3,1fr);gap:14px;margin:18px 0}.stat{background:#10244b;border:1px solid #23497e;border-radius:18px;padding:18px}.stat b{font-size:34px;display:block}.card{background:#0c1d3d;border:1px solid #23497e;border-radius:22px;padding:18px}.toolbar{display:flex;gap:12px;flex-wrap:wrap;margin-bottom:14px}input{padding:13px 15px;border-radius:12px;border:0;min-width:300px;font-size:15px}button,a.btn{display:inline-block;text-decoration:none;background:#0b82e6;color:#fff;border:0;border-radius:12px;padding:13px 16px;font-weight:700;cursor:pointer}.btn.red{background:#c9152b}.tablebox{overflow:auto;border-radius:14px}table{border-collapse:collapse;width:100%;min-width:1000px;background:white;color:#111}th,td{padding:11px 12px;border-bottom:1px solid #e5e7eb;text-align:left;font-size:13px;white-space:nowrap}th{background:#0b326e;color:#fff;position:sticky;top:0}.pill{padding:5px 9px;border-radius:999px;background:#dffce7;color:#14632c;font-weight:700}.small{font-size:12px;color:#cfe3ff;margin-top:10px}@media(max-width:800px){.top{display:block}.grid{grid-template-columns:1fr}input{min-width:100%;width:100%}}
</style></head><body><div class="wrap"><div class="top"><div><h1>NHPC Card Admin Dashboard</h1><div class="user">Signed in as ${String(user.email || '').replace(/[<>]/g, '')}</div></div><div><a class="btn" href="/api/adminExport">Export CSV</a> <a class="btn red" href="/.auth/logout?post_logout_redirect_uri=/api/admin">Logout</a></div></div><div class="grid"><div class="stat"><b>${total}</b>Total unique cards</div><div class="stat"><b>${active}</b>Active cards</div><div class="stat"><b>${today}</b>Generated today</div></div><div class="card"><div class="toolbar"><input id="search" placeholder="Search name, phone, card ID, source..." oninput="render()"><button onclick="copySummary()">Copy Summary</button></div><div class="tablebox"><table><thead><tr><th>#</th><th>Card ID</th><th>Name</th><th>Phone</th><th>Masked</th><th>Status</th><th>Source</th><th>Consent</th><th>Created</th></tr></thead><tbody id="tbody"></tbody></table></div><div class="small">One row per phone number. Older duplicate rows are automatically hidden here.</div></div></div><script>
const rows=${safeRows};
function esc(v){return String(v??'').replace(/[&<>"']/g,m=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[m]))}
function fmt(v){if(!v)return '';try{return new Date(v).toLocaleString()}catch(e){return v}}
function render(){const q=document.getElementById('search').value.toLowerCase();const filtered=rows.filter(r=>!q||[r.uniqueId,r.name,r.phone,r.maskedPhone,r.status,r.source].join(' ').toLowerCase().includes(q));document.getElementById('tbody').innerHTML=filtered.map((r,i)=>'<tr><td>'+(i+1)+'</td><td><b>'+esc(r.uniqueId)+'</b></td><td>'+esc(r.name)+'</td><td>'+esc(r.phone)+'</td><td>'+esc(r.maskedPhone)+'</td><td><span class="pill">'+esc(r.status)+'</span></td><td>'+esc(r.source)+'</td><td>'+(r.consentGiven?'Yes':'No')+'</td><td>'+esc(fmt(r.createdAt))+'</td></tr>').join('')||'<tr><td colspan="9">No records found.</td></tr>'}
function copySummary(){navigator.clipboard.writeText('NHPC Cards: '+rows.length+' total unique cards');alert('Summary copied')}
render();
</script></body></html>`;
}

async function requireAdmin(request) {
  const principal = getClientPrincipal(request);
  if (!principal || !principal.email) return { redirect: true };
  if (!isAllowedAdmin(principal.email)) {
    return { denied: true, principal };
  }
  return { principal };
}

app.http('createCard', {
  methods: ['POST', 'OPTIONS'],
  authLevel: 'anonymous',
  route: 'createCard',
  handler: async (request, context) => {
    if (request.method === 'OPTIONS') return { status: 204, headers: corsHeaders };

    try {
      const body = await request.json().catch(() => ({}));

      if (body.admin === true) {
        return await handleAdminSummary(body);
      }

      if (body.companyWebsite) return json(400, { ok: false, message: 'Invalid request.' });

      const name = cleanName(body.name);
      const phone = cleanPhone(body.phone);
      const consent = body.consent === true;
      const source = String(body.source || 'public-form').slice(0, 40);

      if (!name) return json(400, { ok: false, message: 'Name is required.' });
      if (!/^[0-9]{10}$/.test(phone)) return json(400, { ok: false, message: 'Enter a valid 10-digit WhatsApp number.' });
      if (!consent) return json(400, { ok: false, message: 'Consent is required to generate the card.' });

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

      const uniqueId = makeCardIdFromPhoneHash(phoneHash);
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

      await upsertCard({ partitionKey: 'PHONE', rowKey: phoneHash, ...baseData });
      await upsertCard({ partitionKey: 'CARD', rowKey: uniqueId, ...baseData });

      return json(201, {
        ok: true,
        reused: false,
        uniqueId,
        maskedPhone: maskPhone(phone),
        message: 'Card created successfully.'
      });
    } catch (error) {
      context.error(error);
      return json(500, { ok: false, message: 'Request failed. Please contact the admin.' });
    }
  }
});

app.http('adminDashboard', {
  methods: ['GET'],
  authLevel: 'anonymous',
  route: 'admin',
  handler: async (request, context) => {
    try {
      const auth = await requireAdmin(request);
      if (auth.redirect) return redirectToLogin(request);
      if (auth.denied) return html(403, `<h2>Access denied</h2><p>${auth.principal.email} is not in ADMIN_EMAILS.</p>`);
      const rows = await getAdminRows(5000);
      return html(200, renderAdminPage(rows, auth.principal));
    } catch (error) {
      context.error(error);
      return html(500, '<h2>Admin dashboard failed to load.</h2><p>Check Function App logs and environment variables.</p>');
    }
  }
});

app.http('adminExport', {
  methods: ['GET'],
  authLevel: 'anonymous',
  route: 'adminExport',
  handler: async (request, context) => {
    try {
      const auth = await requireAdmin(request);
      if (auth.redirect) return redirectToLogin(request);
      if (auth.denied) return html(403, `<h2>Access denied</h2><p>${auth.principal.email} is not in ADMIN_EMAILS.</p>`);
      const rows = await getAdminRows(5000);
      const header = ['Card ID', 'Name', 'Phone', 'Masked Phone', 'Status', 'Source', 'Consent', 'Created At', 'Updated At'];
      const lines = [header.map(csvCell).join(',')];
      rows.forEach((row) => {
        lines.push([
          row.uniqueId,
          row.name,
          row.phone,
          row.maskedPhone,
          row.status,
          row.source,
          row.consentGiven ? 'Yes' : 'No',
          row.createdAt,
          row.updatedAt
        ].map(csvCell).join(','));
      });
      return csv(200, lines.join('\n'), 'nhpc-card-database.csv');
    } catch (error) {
      context.error(error);
      return html(500, '<h2>CSV export failed.</h2>');
    }
  }
});
