const crypto = require("crypto");
const { hashPassword } = require("./contrasena");
const { sendTransactionalEmail } = require("./brevo");

const INTERNAL_USER_ROLES = new Set(["admin", "stylist"]);
const STAFF_ROLE_TO_USER_ROLE = {
  Administrador: "admin",
  Estilista: "stylist",
};
const USER_ROLE_TO_STAFF_ROLE = {
  admin: "Administrador",
  stylist: "Estilista",
};
const ACCOUNT_STATUS = {
  ACTIVE: "active",
  PENDING: "pending",
  INACTIVE: "inactive",
};
const INVITE_EXPIRATION_MS = 1000 * 60 * 60 * 24 * 7;
const PASSWORD_RESET_EXPIRATION_MS = 1000 * 60 * 60 * 2;
const DEFAULT_APP_BASE_URL = "https://proyecto-estetica.vercel.app";
const DEFAULT_MOBILE_PASSWORD_RESET_URL =
  "esteticapanamericana:///public/reset-password";

function mapStaffRoleToUserRole(staffRole) {
  return STAFF_ROLE_TO_USER_ROLE[String(staffRole || "").trim()] || null;
}

function mapUserRoleToStaffRole(userRole) {
  return USER_ROLE_TO_STAFF_ROLE[String(userRole || "").trim()] || "";
}

function isInternalUserRole(role) {
  return INTERNAL_USER_ROLES.has(String(role || "").trim());
}

function canUseAdminPanel(role) {
  return String(role || "").trim() === "admin";
}

function normalizeAppBaseUrl(value) {
  const baseUrl = String(value || "").trim() || DEFAULT_APP_BASE_URL;
  return baseUrl.replace(/\/+$/, "");
}

function buildAppUrl(pathname, params = {}) {
  const normalizedBaseUrl = normalizeAppBaseUrl(process.env.APP_BASE_URL);
  const normalizedPath = String(pathname || "/").startsWith("/")
    ? String(pathname || "/")
    : `/${String(pathname || "")}`;
  const url = new URL(`${normalizedBaseUrl}${normalizedPath}`);

  for (const [key, value] of Object.entries(params)) {
    if (value === undefined || value === null || value === "") continue;
    url.searchParams.set(key, String(value));
  }

  return url.toString();
}

function buildMobilePasswordResetUrl(token) {
  const configuredUrl = String(process.env.MOBILE_PASSWORD_RESET_URL || "").trim();
  let url;

  try {
    url = new URL(configuredUrl || DEFAULT_MOBILE_PASSWORD_RESET_URL);
  } catch {
    url = new URL(DEFAULT_MOBILE_PASSWORD_RESET_URL);
  }

  url.searchParams.set("token", String(token || ""));
  return url.toString();
}

function hashAccessToken(token) {
  return crypto.createHash("sha256").update(String(token || "")).digest("hex");
}

function createRawAccessToken() {
  return crypto.randomBytes(32).toString("hex");
}

function createPlaceholderCredentials() {
  const tempPassword = `Tmp-${crypto.randomBytes(24).toString("hex")}Aa1!`;
  return hashPassword(tempPassword);
}

async function revokeAccessTokens(AccountAccessToken, { userId, type = "" }) {
  if (!userId) return;
  const query = { userId };
  if (type) query.type = type;
  await AccountAccessToken.deleteMany(query);
}

async function issueAccessToken(AccountAccessToken, { userId, type, expiresInMs, createdByUserId = null }) {
  await revokeAccessTokens(AccountAccessToken, { userId, type });

  const rawToken = createRawAccessToken();
  const tokenHash = hashAccessToken(rawToken);
  const expiresAt = new Date(Date.now() + expiresInMs);

  const record = await AccountAccessToken.create({
    userId,
    createdByUserId,
    type,
    tokenHash,
    expiresAt,
  });

  return { rawToken, record };
}

async function getValidAccessToken(AccountAccessToken, { token, type }) {
  const tokenHash = hashAccessToken(token);
  if (!tokenHash) return null;

  return AccountAccessToken.findOne({
    tokenHash,
    type,
    usedAt: null,
    expiresAt: { $gt: new Date() },
  });
}

async function consumeAccessToken(AccountAccessToken, { token, type }) {
  const record = await getValidAccessToken(AccountAccessToken, { token, type });
  if (!record) return null;

  record.usedAt = new Date();
  await record.save();
  return record;
}

const CLOUDINARY_LOGO_URL =
  "https://res.cloudinary.com/drnhozxsk/image/upload/estetica-panamericana/logo.png";

function getLogoUrl() {
  return String(process.env.LOGO_URL || "").trim() || CLOUDINARY_LOGO_URL;
}

function buildEmailWrapper({ headerTitle, accentColor, logoUrl, bodyHtml }) {
  return `
<!DOCTYPE html>
<html lang="es">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>${headerTitle}</title>
</head>
<body style="margin:0; padding:0; background-color:#f0f4f8; font-family:'Helvetica Neue', Helvetica, Arial, sans-serif;">
  <table role="presentation" width="100%" cellspacing="0" cellpadding="0" style="background-color:#f0f4f8; padding: 40px 16px;">
    <tr>
      <td align="center">
        <!-- Card -->
        <table role="presentation" width="100%" style="max-width:560px; border-radius:16px; overflow:hidden; box-shadow:0 8px 32px rgba(0,0,0,0.12);">

          <!-- Header con logo -->
          <tr>
            <td align="center" style="background: linear-gradient(135deg, #1a1a2e 0%, #16213e 50%, #0f3460 100%); padding: 36px 32px 28px;">
              <img src="${logoUrl}" alt="Estetica Panamericana" width="130" height="130"
                style="display:block; border-radius:50%; border:3px solid rgba(255,255,255,0.15); object-fit:cover; background:#fff;"
              />
              <p style="margin:14px 0 0; font-size:11px; letter-spacing:3px; text-transform:uppercase; color:rgba(255,255,255,0.55); font-weight:600;">ESTETICA PANAMERICANA</p>
            </td>
          </tr>

          <!-- Título de sección -->
          <tr>
            <td align="center" style="background:${accentColor}; padding:14px 32px;">
              <h1 style="margin:0; font-size:18px; font-weight:700; color:#ffffff; letter-spacing:0.5px;">${headerTitle}</h1>
            </td>
          </tr>

          <!-- Cuerpo del mensaje -->
          <tr>
            <td style="background:#ffffff; padding:36px 40px;">
              ${bodyHtml}
            </td>
          </tr>

          <!-- Footer -->
          <tr>
            <td align="center" style="background:#f8fafc; padding:20px 32px; border-top:1px solid #e2e8f0;">
              <p style="margin:0; font-size:12px; color:#94a3b8; line-height:1.6;">
                Este es un correo automático. Por favor no respondas a este mensaje.<br/>
                &copy; ${new Date().getFullYear()} Estetica Panamericana. Todos los derechos reservados.
              </p>
            </td>
          </tr>

        </table>
      </td>
    </tr>
  </table>
</body>
</html>
  `;
}

function buildInviteEmail(user, token) {
  const roleLabel = mapUserRoleToStaffRole(user.role) || "Personal";
  const link = buildAppUrl("/activar-cuenta", { token });
  const logoUrl = getLogoUrl();

  const bodyHtml = `
    <p style="margin:0 0 8px; font-size:16px; color:#334155;">Hola, <strong>${user.nombre || "equipo"}</strong> 👋</p>
    <p style="margin:0 0 20px; font-size:15px; color:#475569; line-height:1.7;">
      Te damos la bienvenida al equipo de <strong>Estetica Panamericana</strong>.
      Se creó una cuenta para ti con el rol de
      <span style="display:inline-block; background:#f1f5f9; color:#7c3aed; font-weight:700; padding:2px 10px; border-radius:20px; font-size:13px;">${roleLabel}</span>.
    </p>
    <p style="margin:0 0 28px; font-size:15px; color:#475569; line-height:1.7;">
      Para activar tu acceso y establecer tu contraseña, haz clic en el botón a continuación:
    </p>
    <table role="presentation" width="100%" cellspacing="0" cellpadding="0" style="margin-bottom:28px;">
      <tr>
        <td align="center">
          <a href="${link}"
            style="display:inline-block; padding:15px 36px; background:linear-gradient(135deg,#7c3aed,#5b21b6); color:#ffffff; text-decoration:none; border-radius:50px; font-size:15px; font-weight:700; letter-spacing:0.5px; box-shadow:0 4px 14px rgba(124,58,237,0.4);">
            ✅ Activar mi cuenta
          </a>
        </td>
      </tr>
    </table>
    <div style="background:#f8fafc; border-left:3px solid #7c3aed; border-radius:6px; padding:10px 12px; margin-bottom:20px;">
      <p style="margin:0; font-size:11px; font-weight:700; color:#94a3b8; text-transform:uppercase; letter-spacing:1px; line-height:1.2;">¿El botón no funciona?</p>
      <a href="${link}" style="display:block; margin-top:2px; font-size:12px; color:#2563eb; text-decoration:underline; word-break:break-all; line-height:1.35;">${link}</a>
    </div>
    <p style="margin:0; font-size:13px; color:#94a3b8;">⏳ Este enlace vence en <strong>7 días</strong>.</p>
  `;

  return {
    subject: "Activa tu cuenta de Estetica Panamericana",
    htmlContent: buildEmailWrapper({
      headerTitle: "Activación de Cuenta",
      accentColor: "#7c3aed",
      logoUrl,
      bodyHtml,
    }),
    textContent: `Hola ${user.nombre || "equipo"}, activa tu cuenta aqui: ${link}. Este enlace vence en 7 dias.`,
  };
}

function buildPasswordResetEmail(user, token, { openInMobileApp = false } = {}) {
  const webLink = buildAppUrl("/restablecer-contrasena", { token });
  const link = openInMobileApp ? buildMobilePasswordResetUrl(token) : webLink;
  const webFallbackHtml = openInMobileApp
    ? `
      <p style="margin:16px 0 6px; font-size:12px; color:#64748b; line-height:1.5;">
        Si no tienes la aplicaci&oacute;n instalada, tambi&eacute;n puedes continuar desde el sitio web:
      </p>
      <a href="${webLink}" style="font-size:12px; color:#2563eb; text-decoration:underline; word-break:break-all; line-height:1.35;">${webLink}</a>
    `
    : "";
  const logoUrl = getLogoUrl();

  const bodyHtml = `
    <p style="margin:0 0 8px; font-size:16px; color:#334155;">Hola, <strong>${user.nombre || "usuario"}</strong></p>
    <p style="margin:0 0 20px; font-size:15px; color:#475569; line-height:1.7;">
      Recibimos una solicitud para restablecer la contraseña de tu cuenta en <strong>Estetica Panamericana</strong>.
      Si no fuiste tú quien lo solicitó, puedes ignorar este correo con total tranquilidad.
    </p>
    <p style="margin:0 0 28px; font-size:15px; color:#475569; line-height:1.7;">
      Haz clic en el botón a continuación para establecer una nueva contraseña:
    </p>
    <table role="presentation" width="100%" cellspacing="0" cellpadding="0" style="margin-bottom:28px;">
      <tr>
        <td align="center">
          <a href="${link}"
            style="display:inline-block; padding:15px 36px; background:linear-gradient(135deg,#0f766e,#065f46); color:#ffffff; text-decoration:none; border-radius:50px; font-size:15px; font-weight:700; letter-spacing:0.5px; box-shadow:0 4px 14px rgba(15,118,110,0.4);">
            🔑 Restablecer contraseña
          </a>
        </td>
      </tr>
    </table>
    <div style="background:#f8fafc; border-left:3px solid #0f766e; border-radius:6px; padding:10px 12px; margin-bottom:20px;">
      <p style="margin:0; font-size:11px; font-weight:700; color:#94a3b8; text-transform:uppercase; letter-spacing:1px; line-height:1.2;">¿El botón no funciona?</p>
      <a href="${link}" style="display:block; margin-top:2px; font-size:12px; color:#2563eb; text-decoration:underline; word-break:break-all; line-height:1.35;">${link}</a>
      ${webFallbackHtml}
    </div>
    <p style="margin:0; font-size:13px; color:#94a3b8;">⏳ Este enlace vence en <strong>2 horas</strong>.</p>
  `;

  return {
    subject: "Restablece tu contraseña de Estetica Panamericana",
    htmlContent: buildEmailWrapper({
      headerTitle: "Restablecer Contraseña",
      accentColor: "#0f766e",
      logoUrl,
      bodyHtml,
    }),
    textContent: `Hola ${user.nombre || "usuario"}, restablece tu contraseña aqui: ${link}. Este enlace vence en 2 horas.`,
  };
}

async function sendInviteEmail(user, token) {
  const email = buildInviteEmail(user, token);
  return sendTransactionalEmail({
    to: { email: user.correo, name: user.nombre || "" },
    subject: email.subject,
    htmlContent: email.htmlContent,
  });
}

async function sendPasswordResetEmail(user, token, options = {}) {
  const email = buildPasswordResetEmail(user, token, options);
  return sendTransactionalEmail({
    to: { email: user.correo, name: user.nombre || "" },
    subject: email.subject,
    htmlContent: email.htmlContent,
  });
}

module.exports = {
  ACCOUNT_STATUS,
  INVITE_EXPIRATION_MS,
  PASSWORD_RESET_EXPIRATION_MS,
  canUseAdminPanel,
  consumeAccessToken,
  createPlaceholderCredentials,
  getValidAccessToken,
  isInternalUserRole,
  issueAccessToken,
  mapStaffRoleToUserRole,
  mapUserRoleToStaffRole,
  revokeAccessTokens,
  sendInviteEmail,
  sendPasswordResetEmail,
};
