const { cert, getApps, initializeApp } = require("firebase-admin/app");
const { getAuth } = require("firebase-admin/auth");

class FirebaseAdminConfigurationError extends Error {
  constructor(message) {
    super(message);
    this.name = "FirebaseAdminConfigurationError";
  }
}

function readRequiredEnvironmentValue(name) {
  const value = String(process.env[name] || "").trim();
  if (!value) {
    throw new FirebaseAdminConfigurationError(`Falta configurar ${name}.`);
  }
  return value;
}

function getFirebaseAdminApp() {
  const existingApp = getApps()[0];
  if (existingApp) return existingApp;

  const projectId = readRequiredEnvironmentValue("FIREBASE_PROJECT_ID");
  const clientEmail = readRequiredEnvironmentValue("FIREBASE_CLIENT_EMAIL");
  const privateKey = readRequiredEnvironmentValue("FIREBASE_PRIVATE_KEY").replace(/\\n/g, "\n");

  return initializeApp({
    credential: cert({ clientEmail, privateKey, projectId }),
    projectId,
  });
}

function getFirebaseAdminAuth() {
  return getAuth(getFirebaseAdminApp());
}

module.exports = {
  FirebaseAdminConfigurationError,
  getFirebaseAdminAuth,
};
