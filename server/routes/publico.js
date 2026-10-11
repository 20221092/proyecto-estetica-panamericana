const express = require("express");
const mongoose = require("mongoose");
const User = require("../models/Usuario");
const AccountAccessToken = require("../models/TokenAccesoCuenta");
const ProductCategory = require("../models/CategoriaProducto");
const ProductBrand = require("../models/MarcaProducto");
const Product = require("../models/Producto");
const ServiceCategory = require("../models/CategoriaServicio");
const Service = require("../models/Servicio");
const CompanyInfo = require("../models/InformacionEmpresa");
const CarouselSlide = require("../models/DiapositivaCarrusel");
const Promotion = require("../models/Promocion");
const { hashPassword, verifyPassword } = require("../utils/contrasena");
const { createToken } = require("../utils/auth");
const {
  ACCOUNT_STATUS,
  INVITE_EXPIRATION_MS,
  PASSWORD_RESET_EXPIRATION_MS,
  getValidAccessToken,
  isInternalUserRole,
  issueAccessToken,
  sendInviteEmail,
  sendPasswordResetEmail,
} = require("../utils/accountAccess");
const {
  normalizeString,
  validateName,
  validateEmail,
  validatePhone,
  validatePassword,
} = require("../utils/validadores");
const { normalizeServiceSegmentInRecord } = require("../utils/serviceSegments");

const router = express.Router();

function isValidId(id) {
  return mongoose.Types.ObjectId.isValid(id);
}

function mapId(record) {
  if (!record) return null;
  const mappedRecord = {
    id: record._id.toString(),
    ...record,
    _id: undefined,
    __v: undefined,
  };
  return normalizeServiceSegmentInRecord(mappedRecord);
}

function mapCompanyInfo(record) {
  const source = record || {};
  return {
    nombre: source.nombre || "",
    direccion: source.direccion || "",
    telefono: source.telefono || "",
    email: source.email || "",
    mision: source.mision || "",
    vision: source.vision || "",
    valores: source.valores || "",
    facebook: source.facebook || "",
    instagram: source.instagram || "",
    quienesSomosTexto: source.quienesSomosTexto || "",
    quienesSomosEsencia: source.quienesSomosEsencia || "",
    horarioLunesSabado: source.horarioLunesSabado || "",
    horarioDomingo: source.horarioDomingo || "",
    mapLat: source.mapLat || "",
    mapLng: source.mapLng || "",
    mapZoom: source.mapZoom || "15",
    mapGoogleUrl: source.mapGoogleUrl || "",
    politicasDocumento: source.politicasDocumento || "",
    politicasDocumentoNombre: source.politicasDocumentoNombre || "",
    politicasDocumentoTipo: source.politicasDocumentoTipo || "",
  };
}

function normalizeEmail(value) {
  return normalizeString(value).toLowerCase();
}

function buildUserResponse(user) {
  return {
    id: String(user._id),
    nombre: user.nombre,
    apellidoPaterno: user.apellidoPaterno,
    apellidoMaterno: user.apellidoMaterno,
    telefono: user.telefono,
    correo: user.correo,
    role: user.role,
    accountStatus: user.accountStatus || ACCOUNT_STATUS.ACTIVE,
  };
}

function buildBlockedLoginMessage(user) {
  if (!user) return "Credenciales invalidas.";
  if (user.accountStatus === ACCOUNT_STATUS.PENDING) {
    return "Tu cuenta aun no esta activada. Revisa el enlace enviado a tu correo.";
  }
  if (user.accountStatus === ACCOUNT_STATUS.INACTIVE) {
    return "Tu cuenta esta inactiva. Contacta al administrador.";
  }
  return "";
}

async function resolveTokenUser(token, type) {
  const record = await getValidAccessToken(AccountAccessToken, { token, type });
  if (!record) return { record: null, user: null };

  const user = await User.findById(record.userId);
  if (!user) return { record: null, user: null };

  return { record, user };
}

router.post("/register", async (req, res) => {
  try {
    const errors = [];
    const { nombre, apellidoPaterno, apellidoMaterno, telefono, correo, password } = req.body;

    validateName(nombre, "Nombre", errors);
    validateName(apellidoPaterno, "Apellido paterno", errors);
    validateName(apellidoMaterno, "Apellido materno", errors);
    validatePhone(telefono, errors);
    validateEmail(correo, errors);
    validatePassword(password, errors);

    if (errors.length) {
      return res.status(400).json({ errors });
    }

    const normalizedEmail = normalizeEmail(correo);
    const normalizedPhone = normalizeString(telefono);

    const existingByEmail = normalizedEmail
      ? User.findOne({ correo: { $eq: normalizedEmail } })
      : Promise.resolve(null);
    const existingByPhone = normalizedPhone
      ? User.findOne({ telefono: { $eq: normalizedPhone } })
      : Promise.resolve(null);
    const [existingEmail, existingPhone] = await Promise.all([existingByEmail, existingByPhone]);

    if (existingEmail || existingPhone) {
      return res.status(409).json({
        errors: ["El correo o telefono ya estan registrados."],
      });
    }

    const { hash, salt } = hashPassword(password);
    const user = await User.create({
      nombre: normalizeString(nombre),
      apellidoPaterno: normalizeString(apellidoPaterno),
      apellidoMaterno: normalizeString(apellidoMaterno),
      telefono: normalizedPhone,
      correo: normalizedEmail,
      passwordHash: hash,
      passwordSalt: salt,
      role: "client",
    });

    return res.status(201).json({
      message: "Registro exitoso.",
      token: createToken({ id: user._id, correo: user.correo, role: user.role }),
      user: buildUserResponse(user),
    });
  } catch (error) {
    if (error?.code === 11000) {
      return res.status(409).json({
        errors: ["El correo o telefono ya estan registrados."],
      });
    }

    console.error("Error en /api/public/register:", error);
    return res.status(500).json({
      errors: ["No fue posible completar el registro."],
    });
  }
});

router.post("/login", async (req, res) => {
  const errors = [];
  const { correo, password } = req.body;
  const identifier = normalizeEmail(correo);

  if (!identifier) {
    errors.push("Correo o usuario es obligatorio.");
  }
  if (!password) {
    errors.push("Contrasena es obligatoria.");
  }

  if (errors.length) {
    return res.status(400).json({ errors });
  }

  // Login por correo o username: se consulta con valores exactos sanitizados y separados por campo.
  const [userByEmail, userByUsername] = await Promise.all([
    identifier ? User.findOne({ correo: { $eq: identifier } }) : Promise.resolve(null),
    identifier ? User.findOne({ username: { $eq: identifier } }) : Promise.resolve(null),
  ]);
  const user = userByEmail || userByUsername;
  if (!user) {
    return res.status(401).json({ errors: ["Credenciales invalidas."] });
  }

  const isValid = verifyPassword(password, user.passwordSalt, user.passwordHash);
  if (!isValid) {
    return res.status(401).json({ errors: ["Credenciales invalidas."] });
  }

  const blockedMessage = buildBlockedLoginMessage(user);
  if (blockedMessage) {
    return res.status(403).json({ errors: [blockedMessage] });
  }

  return res.json({
    message: "Inicio de sesion correcto.",
    token: createToken({ id: user._id, correo: user.correo, role: user.role }),
    user: buildUserResponse(user),
  });
});

router.post("/recover", async (req, res) => {
  try {
    const errors = [];
    const { correo } = req.body;
    const openInMobileApp = normalizeString(req.body.origen).toLowerCase() === "movil";
    validateEmail(correo, errors);

    if (errors.length) {
      return res.status(400).json({ errors });
    }

    const normalizedRecoverEmail = normalizeEmail(correo);
    const user = await User.findOne({ correo: { $eq: normalizedRecoverEmail } });
    if (!user) {
      return res.status(404).json({ errors: ["No existe una cuenta con ese correo."] });
    }

    if (user.accountStatus === ACCOUNT_STATUS.INACTIVE) {
      return res.status(403).json({ errors: ["La cuenta esta inactiva. Contacta al administrador."] });
    }

    if (user.accountStatus === ACCOUNT_STATUS.PENDING && isInternalUserRole(user.role)) {
      const { rawToken } = await issueAccessToken(AccountAccessToken, {
        userId: user._id,
        type: "invite",
        expiresInMs: INVITE_EXPIRATION_MS,
      });
      await sendInviteEmail(user, rawToken);
      user.inviteSentAt = new Date();
      await user.save();

      return res.json({
        message: "Tu cuenta aun no esta activada. Se reenvio el enlace de activacion al correo.",
      });
    }

    const { rawToken } = await issueAccessToken(AccountAccessToken, {
      userId: user._id,
      type: "password_reset",
      expiresInMs: PASSWORD_RESET_EXPIRATION_MS,
    });
    await sendPasswordResetEmail(user, rawToken, { openInMobileApp });
    user.passwordResetSentAt = new Date();
    await user.save();

    return res.json({
      message: "Se envio un enlace de recuperacion al correo.",
    });
  } catch (error) {
    console.error("Error en /api/public/recover:", error);
    return res.status(500).json({
      errors: ["No fue posible enviar el correo de recuperacion."],
    });
  }
});

router.get("/invite/validate", async (req, res) => {
  const token = normalizeString(req.query.token);
  if (!token) {
    return res.status(400).json({ errors: ["Token de invitacion invalido."] });
  }

  const { user } = await resolveTokenUser(token, "invite");
  if (!user) {
    return res.status(404).json({ errors: ["La invitacion no existe o ya vencio."] });
  }

  if (user.accountStatus === ACCOUNT_STATUS.INACTIVE) {
    return res.status(403).json({ errors: ["La cuenta esta inactiva. Contacta al administrador."] });
  }

  return res.json({
    user: {
      nombre: user.nombre,
      correo: user.correo,
      role: user.role,
    },
  });
});

router.post("/invite/accept", async (req, res) => {
  try {
    const token = normalizeString(req.body.token);
    const password = req.body.password || "";
    const errors = [];

    if (!token) errors.push("Token de invitacion invalido.");
    validatePassword(password, errors);
    if (errors.length) {
      return res.status(400).json({ errors });
    }

    const { record, user } = await resolveTokenUser(token, "invite");
    if (!record || !user) {
      return res.status(404).json({ errors: ["La invitacion no existe o ya vencio."] });
    }

    if (user.accountStatus === ACCOUNT_STATUS.INACTIVE) {
      return res.status(403).json({ errors: ["La cuenta esta inactiva. Contacta al administrador."] });
    }

    const { hash, salt } = hashPassword(password);
    user.passwordHash = hash;
    user.passwordSalt = salt;
    user.passwordSetupRequired = false;
    user.accountStatus = ACCOUNT_STATUS.ACTIVE;
    user.activatedAt = new Date();
    record.usedAt = new Date();
    await user.save();
    await record.save();

    await AccountAccessToken.deleteMany({ userId: user._id, type: "password_reset" });

    return res.json({
      message: "Cuenta activada correctamente. Ya puedes iniciar sesion.",
    });
  } catch (error) {
    console.error("Error en /api/public/invite/accept:", error);
    return res.status(500).json({
      errors: ["No fue posible activar la cuenta."],
    });
  }
});

router.get("/reset-password/validate", async (req, res) => {
  const token = normalizeString(req.query.token);
  if (!token) {
    return res.status(400).json({ errors: ["Token de recuperacion invalido."] });
  }

  const { user } = await resolveTokenUser(token, "password_reset");
  if (!user) {
    return res.status(404).json({ errors: ["El enlace de recuperacion no existe o ya vencio."] });
  }

  if (user.accountStatus !== ACCOUNT_STATUS.ACTIVE) {
    return res.status(403).json({ errors: ["La cuenta no esta disponible para restablecer contrasena."] });
  }

  return res.json({
    user: {
      nombre: user.nombre,
      correo: user.correo,
      role: user.role,
    },
  });
});

router.post("/reset-password", async (req, res) => {
  try {
    const token = normalizeString(req.body.token);
    const password = req.body.password || "";
    const errors = [];

    if (!token) errors.push("Token de recuperacion invalido.");
    validatePassword(password, errors);
    if (errors.length) {
      return res.status(400).json({ errors });
    }

    const { record, user } = await resolveTokenUser(token, "password_reset");
    if (!record || !user) {
      return res.status(404).json({ errors: ["El enlace de recuperacion no existe o ya vencio."] });
    }

    if (user.accountStatus !== ACCOUNT_STATUS.ACTIVE) {
      return res.status(403).json({ errors: ["La cuenta no esta disponible para restablecer contrasena."] });
    }

    const { hash, salt } = hashPassword(password);
    user.passwordHash = hash;
    user.passwordSalt = salt;
    user.passwordSetupRequired = false;
    record.usedAt = new Date();
    await user.save();
    await record.save();

    return res.json({
      message: "Contrasena actualizada correctamente. Ya puedes iniciar sesion.",
    });
  } catch (error) {
    console.error("Error en /api/public/reset-password:", error);
    return res.status(500).json({
      errors: ["No fue posible actualizar la contrasena."],
    });
  }
});

router.get("/company-info", async (_req, res) => {
  const record = await CompanyInfo.findOne({ key: "main" }).lean();
  return res.json({ companyInfo: mapCompanyInfo(record) });
});

router.get("/product-categories", async (_req, res) => {
  const categories = await ProductCategory.find({ estado: "Activa" }).sort({ nombre: 1 }).lean();
  return res.json({ categories: categories.map(mapId) });
});

router.get("/product-brands", async (_req, res) => {
  const brands = await ProductBrand.find({ estado: "Activa" }).sort({ nombre: 1 }).lean();
  return res.json({ brands: brands.map(mapId) });
});

router.get("/products", async (_req, res) => {
  const products = await Product.find().sort({ createdAt: -1 }).lean();
  return res.json({ products: products.map(mapId) });
});

router.get("/products/:id", async (req, res) => {
  if (!isValidId(req.params.id)) {
    return res.status(404).json({ errors: ["Producto no encontrado."] });
  }
  // findById reemplazado por ObjectId estrictamente construido desde parametro validado.
  const product = await Product.findOne({ _id: { $eq: new mongoose.Types.ObjectId(req.params.id) } }).lean();
  if (!product) {
    return res.status(404).json({ errors: ["Producto no encontrado."] });
  }
  return res.json({ product: mapId(product) });
});

router.get("/service-categories", async (_req, res) => {
  const categories = await ServiceCategory.find({ estado: "Activa" }).sort({ segmento: 1, nombre: 1 }).lean();
  return res.json({ categories: categories.map(mapId) });
});

router.get("/services", async (_req, res) => {
  const services = await Service.find().sort({ createdAt: -1 }).lean();
  return res.json({ services: services.map(mapId) });
});

router.get("/services/:id", async (req, res) => {
  if (!isValidId(req.params.id)) {
    return res.status(404).json({ errors: ["Servicio no encontrado."] });
  }

  const service = await Service.findOne({ _id: { $eq: new mongoose.Types.ObjectId(req.params.id) } }).lean();
  if (!service) {
    return res.status(404).json({ errors: ["Servicio no encontrado."] });
  }

  return res.json({ service: mapId(service) });
});

router.get("/promotions", async (_req, res) => {
  const promotions = await Promotion.find({ estado: "Activa" }).sort({ createdAt: -1 }).lean();
  return res.json({ promotions: promotions.map(mapId) });
});

router.get("/home-highlights", async (_req, res) => {
  const [products, services, promotions] = await Promise.all([
    Product.find({ destacadoInicio: true }).sort({ createdAt: -1 }).limit(4).lean(),
    Service.find({ destacadoInicio: true }).sort({ createdAt: -1 }).limit(4).lean(),
    Promotion.find({ estado: "Activa", destacadoInicio: true }).sort({ createdAt: -1 }).limit(4).lean(),
  ]);

  return res.json({
    products: products.map(mapId),
    services: services.map(mapId),
    promotions: promotions.map(mapId),
  });
});

router.get("/carousel", async (_req, res) => {
  const slides = await CarouselSlide.find({ estado: "Activa" }).sort({ orden: 1, createdAt: 1 }).lean();
  return res.json({ slides: slides.map(mapId) });
});

router.get("/bootstrap", async (_req, res) => {
  const [company, categories, brands, products, serviceCategories, services, promotions, slides] = await Promise.all([
    CompanyInfo.findOne({ key: "main" }).lean(),
    ProductCategory.find({ estado: "Activa" }).sort({ nombre: 1 }).lean(),
    ProductBrand.find({ estado: "Activa" }).sort({ nombre: 1 }).lean(),
    Product.find().sort({ createdAt: -1 }).lean(),
    ServiceCategory.find({ estado: "Activa" }).sort({ segmento: 1, nombre: 1 }).lean(),
    Service.find().sort({ createdAt: -1 }).lean(),
    Promotion.find({ estado: "Activa" }).sort({ createdAt: -1 }).lean(),
    CarouselSlide.find({ estado: "Activa" }).sort({ orden: 1, createdAt: 1 }).lean(),
  ]);

  return res.json({
    companyInfo: mapCompanyInfo(company),
    productCategories: categories.map(mapId),
    productBrands: brands.map(mapId),
    products: products.map(mapId),
    serviceCategories: serviceCategories.map(mapId),
    services: services.map(mapId),
    promotions: promotions.map(mapId),
    carouselSlides: slides.map(mapId),
  });
});

module.exports = router;
