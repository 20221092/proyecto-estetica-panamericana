require("dotenv").config();
const mongoose = require("mongoose");
const User = require("../models/Usuario");

const INDEX_DEFINITIONS = [
  {
    field: "telefono",
    name: "telefono_unique_sparse",
  },
  {
    field: "firebaseUid",
    name: "firebase_uid_unique_sparse",
  },
];

function hasKey(index, field) {
  return Object.keys(index.key || {}).length === 1 && index.key?.[field] === 1;
}

function hasExpectedOptions(index) {
  return index.unique === true && index.sparse === true;
}

async function validateIndexData(collection, field) {
  const invalidValue = await collection.findOne({
    $or: [
      { [field]: { $type: "null" } },
      { [field]: { $type: "string", $regex: /^\s*$/ } },
    ],
  });

  if (invalidValue) {
    throw new Error(
      `El campo ${field} contiene null o texto vacio. Normaliza esos registros antes de migrar.`,
    );
  }

  const duplicateValues = await collection.aggregate([
    { $match: { [field]: { $exists: true } } },
    { $group: { _id: `$${field}`, count: { $sum: 1 } } },
    { $match: { count: { $gt: 1 } } },
    { $limit: 1 },
  ]).toArray();

  if (duplicateValues.length) {
    throw new Error(`El campo ${field} contiene valores duplicados.`);
  }
}

async function ensureSparseUniqueIndex(collection, definition) {
  const { field, name } = definition;
  await validateIndexData(collection, field);

  let indexes = await collection.indexes();
  const namedIndex = indexes.find((index) => index.name === name);

  if (namedIndex && (!hasKey(namedIndex, field) || !hasExpectedOptions(namedIndex))) {
    throw new Error(`El indice ${name} existe con una configuracion incompatible.`);
  }

  if (!namedIndex) {
    await collection.createIndex(
      { [field]: 1 },
      { name, sparse: true, unique: true },
    );
  }

  indexes = await collection.indexes();
  const verifiedIndex = indexes.find((index) => index.name === name);
  if (!verifiedIndex || !hasKey(verifiedIndex, field) || !hasExpectedOptions(verifiedIndex)) {
    throw new Error(`No fue posible verificar el indice ${name}.`);
  }

  const obsoleteIndexes = indexes.filter(
    (index) => index.name !== name && hasKey(index, field),
  );
  for (const obsoleteIndex of obsoleteIndexes) {
    await collection.dropIndex(obsoleteIndex.name);
  }
}

async function run() {
  if (!process.env.MONGODB_URI) {
    throw new Error("Falta configurar MONGODB_URI.");
  }

  await mongoose.connect(process.env.MONGODB_URI, {
    autoIndex: false,
    dbName: process.env.MONGODB_DB_NAME || "Estetica_Panamericana",
  });

  for (const definition of INDEX_DEFINITIONS) {
    await ensureSparseUniqueIndex(User.collection, definition);
  }

  console.log("Indices para autenticacion con Google verificados correctamente.");
}

run()
  .catch((error) => {
    console.error("No fue posible actualizar los indices de usuarios:", error.message);
    process.exitCode = 1;
  })
  .finally(async () => {
    await mongoose.disconnect();
  });
