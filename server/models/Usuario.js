const mongoose = require("mongoose");

function normalizeOptionalUsername(value) {
  if (typeof value !== "string") return undefined;
  const normalized = value.trim().toLowerCase();
  return normalized || undefined;
}

function normalizeOptionalValue(value) {
  if (typeof value !== "string") return undefined;
  const normalized = value.trim();
  return normalized || undefined;
}

const userSchema = new mongoose.Schema(
  {
    username: { type: String, unique: true, sparse: true, default: undefined, set: normalizeOptionalUsername },
    firebaseUid: { type: String, default: undefined, set: normalizeOptionalValue },
    nombre: { type: String, required: true, trim: true },
    apellidoPaterno: { type: String, trim: true, default: "" },
    apellidoMaterno: { type: String, trim: true, default: "" },
    telefono: {
      type: String,
      required() { return !this.firebaseUid; },
      default: undefined,
      set: normalizeOptionalValue,
    },
    correo: { type: String, required: true, unique: true, lowercase: true },
    passwordHash: { type: String, required() { return !this.firebaseUid; }, default: undefined },
    passwordSalt: { type: String, required() { return !this.firebaseUid; }, default: undefined },
    role: { type: String, enum: ["client", "admin", "stylist"], default: "client", index: true },
    accountStatus: { type: String, enum: ["active", "pending", "inactive"], default: "active", index: true },
    passwordSetupRequired: { type: Boolean, default: false },
    inviteSentAt: { type: Date, default: null },
    passwordResetSentAt: { type: Date, default: null },
    activatedAt: { type: Date, default: null },
    reminderSettings: {
      anticipacion: { type: String, default: "24 horas antes" },
      canal: { type: String, default: "Email" },
    },
    notificationPreferences: {
      appointmentReminders: { type: Boolean, default: true },
      promotions: { type: Boolean, default: true },
      appointmentChanges: { type: Boolean, default: true },
    },
  },
  { timestamps: true, collection: "usuarios" }
);

userSchema.index(
  { firebaseUid: 1 },
  { name: "firebase_uid_unique_sparse", sparse: true, unique: true }
);
userSchema.index(
  { telefono: 1 },
  { name: "telefono_unique_sparse", sparse: true, unique: true }
);

module.exports = mongoose.model("User", userSchema);
