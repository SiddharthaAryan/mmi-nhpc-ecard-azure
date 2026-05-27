const { TableClient, AzureNamedKeyCredential } = require('@azure/data-tables');

let clientPromise;

function getTableName() {
  return process.env.TABLE_NAME || 'NhpcCards';
}

async function getTableClient() {
  if (clientPromise) return clientPromise;

  const connectionString = process.env.AZURE_STORAGE_CONNECTION_STRING;
  if (!connectionString) {
    throw new Error('Missing AZURE_STORAGE_CONNECTION_STRING.');
  }

  const client = TableClient.fromConnectionString(connectionString, getTableName());
  clientPromise = (async () => {
    await client.createTable().catch((error) => {
      if (error.statusCode !== 409) throw error;
    });
    return client;
  })();

  return clientPromise;
}

function safeEntity(entity) {
  const copy = { ...entity };
  delete copy.etag;
  return copy;
}

async function upsertCard(entity) {
  const client = await getTableClient();
  await client.upsertEntity(entity, 'Merge');
  return safeEntity(entity);
}

async function getCardByPhoneHash(phoneHash) {
  const client = await getTableClient();
  try {
    return await client.getEntity('PHONE', phoneHash);
  } catch (error) {
    if (error.statusCode === 404) return null;
    throw error;
  }
}

async function getCardById(cardId) {
  const client = await getTableClient();
  try {
    return await client.getEntity('CARD', cardId);
  } catch (error) {
    if (error.statusCode === 404) return null;
    throw error;
  }
}

async function listCards(limit = 50) {
  const client = await getTableClient();
  const rows = [];
  const entities = client.listEntities({
    queryOptions: {
      filter: `PartitionKey eq 'CARD'`
    }
  });

  for await (const entity of entities) {
    rows.push(entity);
    if (rows.length >= limit) break;
  }

  rows.sort((a, b) => String(b.createdAt || '').localeCompare(String(a.createdAt || '')));
  return rows;
}

module.exports = {
  getTableClient,
  upsertCard,
  getCardByPhoneHash,
  getCardById,
  listCards
};
