// ============================================================
//  LAUNGE BACKEND — Bloc 1 : fondations de sécurité
//  - Clé secrète Supabase (accès complet réservé au serveur)
//  - Jetons de connexion vérifiés + rôles (restaurant, cuisine, admin)
//  - Session par cookie sécurisé (HttpOnly) OU par en-tête Authorization
//  - Isolation entre restaurants
//  - Limitation des tentatives, validation des données
//  - Envoi des photos de plats via le serveur
//  Aucune nouvelle dépendance : package.json ne change pas.
// ============================================================
const crypto = require('crypto');
const express = require('express');
const cors = require('cors');
const dotenv = require('dotenv');
const { createClient } = require('@supabase/supabase-js');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

dotenv.config();

/* ───────────────────────── Configuration ───────────────────────── */
const JWT_SECRET = process.env.JWT_SECRET;
if (!JWT_SECRET) {
  console.error('❌ JWT_SECRET est manquant : le serveur ne peut pas démarrer.');
  process.exit(1);
}
if (JWT_SECRET.length < 32) console.warn('⚠️  JWT_SECRET est court : utilisez au moins 32 caractères.');

const CLE_SECRETE = process.env.SUPABASE_SECRET_KEY;
if (!CLE_SECRETE) console.warn('⚠️  SUPABASE_SECRET_KEY absente : utilisation de SUPABASE_KEY (accès limité).');

const supabase = createClient(process.env.SUPABASE_URL, CLE_SECRETE || process.env.SUPABASE_KEY, {
  auth: { persistSession: false, autoRefreshToken: false },
});

// AUTH_STRICT=true  → toutes les routes protégées exigent une connexion.
// Sinon (période de transition) : les appels sans jeton sont tolérés et signalés dans les logs.
const AUTH_STRICT = process.env.AUTH_STRICT === 'true';
// Adresses autorisées à appeler l'API, séparées par des virgules.
const ORIGINES = (process.env.CORS_ORIGINS || '').split(',').map((s) => s.trim()).filter(Boolean);

const BUCKET = 'plats';
const PREFIXE_IMAGES = supabase.storage.from(BUCKET).getPublicUrl('_').data.publicUrl.slice(0, -1);
const STATUTS_BLOQUES = ['en_attente', 'refuse'];
const NOM_COOKIE = 'launge_session';
const DUREE_SESSION_MS = 7 * 24 * 60 * 60 * 1000;
const HASH_FACTICE = bcrypt.hashSync(crypto.randomBytes(8).toString('hex'), 10);

/* ───────────────────────── Outils ───────────────────────── */
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const estUuid = (v) => typeof v === 'string' && UUID.test(v);
const texte = (v, max) => (typeof v === 'string' ? v.trim().slice(0, max) : '');
const entier = (v, min, max) => {
  if (v === '' || v === null || typeof v === 'boolean') return null;
  const n = Number(v);
  return Number.isInteger(n) && n >= min && n <= max ? n : null;
};
const emailValide = (e) => /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(e);
const nettoyerResto = (r) => {
  if (!r) return r;
  const { mot_de_passe, ...reste } = r;
  return reste;
};
const egal = (a, b) => {
  const A = Buffer.from(String(a));
  const B = Buffer.from(String(b));
  return A.length === B.length && crypto.timingSafeEqual(A, B);
};
const echapperIlike = (s) => s.replace(/[\\%_]/g, (m) => '\\' + m);
const chercherParEmail = (table, email) =>
  supabase.from(table).select('*').ilike('email', echapperIlike(email)).limit(1).maybeSingle();
const echec = (res, contexte, error) => {
  console.error(`[BASE] ${contexte} :`, (error && error.message) || error);
  return res.status(500).json({ error: 'Une erreur est survenue. Réessayez dans un instant.' });
};
const validerUuid = (...noms) => (req, res, next) => {
  for (const n of noms) if (!estUuid(req.params[n])) return res.status(400).json({ error: 'Identifiant invalide.' });
  next();
};

/* ───────────────────── Limitation des tentatives ───────────────────── */
const compteurs = new Map();
function limiter(nom, max, fenetreMs, cle) {
  return (req, res, next) => {
    const k = `${nom}:${cle(req)}`;
    const now = Date.now();
    let e = compteurs.get(k);
    if (!e || e.fin <= now) {
      e = { n: 0, fin: now + fenetreMs };
      compteurs.set(k, e);
    }
    e.n += 1;
    if (e.n > max) {
      res.set('Retry-After', String(Math.ceil((e.fin - now) / 1000)));
      return res.status(429).json({ error: 'Trop de tentatives. Réessayez plus tard.' });
    }
    next();
  };
}
setInterval(() => {
  const now = Date.now();
  for (const [k, e] of compteurs) if (e.fin <= now) compteurs.delete(k);
}, 60000).unref();
const parIp = (req) => req.ip || 'inconnue';
const parEmail = (req) => texte(req.body && req.body.email, 150).toLowerCase() || 'vide';

/* ───────────────────── Session : jeton + cookie ───────────────────── */
const signer = (payload) => jwt.sign(payload, JWT_SECRET, { algorithm: 'HS256', expiresIn: '7d', issuer: 'launge' });

function lireCookie(req, nom) {
  const brut = req.headers.cookie;
  if (!brut) return null;
  for (const morceau of brut.split(';')) {
    const i = morceau.indexOf('=');
    if (i === -1) continue;
    if (morceau.slice(0, i).trim() === nom) {
      try { return decodeURIComponent(morceau.slice(i + 1).trim()); } catch { return null; }
    }
  }
  return null;
}
// Cookie inaccessible au JavaScript (HttpOnly), uniquement en HTTPS (Secure).
// SameSite=None car le site (Vercel) et l'API (Railway) sont sur des domaines différents.
const OPTIONS_COOKIE = { httpOnly: true, secure: true, sameSite: 'none', path: '/' };
function ouvrirSession(res, payload) {
  const token = signer(payload);
  res.cookie(NOM_COOKIE, token, { ...OPTIONS_COOKIE, maxAge: DUREE_SESSION_MS });
  return token;
}

function authentifier(req, res, next) {
  req.auth = null;
  req.viaCookie = false;
  req.jetonInvalide = false;
  let jeton = null;
  const h = req.headers.authorization;
  if (h) {
    if (h.startsWith('Bearer ')) jeton = h.slice(7);
    else req.jetonInvalide = true;
  } else {
    jeton = lireCookie(req, NOM_COOKIE);
    req.viaCookie = Boolean(jeton);
  }
  if (jeton) {
    try {
      req.auth = jwt.verify(jeton, JWT_SECRET, { algorithms: ['HS256'], issuer: 'launge' });
    } catch {
      req.jetonInvalide = true;
      req.viaCookie = false;
    }
  }
  next();
}

// Protège une route. `toujours: true` = connexion exigée même pendant la transition.
function exiger(roles, { toujours = false } = {}) {
  return (req, res, next) => {
    if (req.jetonInvalide) return res.status(401).json({ error: 'Session expirée. Reconnectez-vous.' });
    if (!req.auth) {
      if (AUTH_STRICT || toujours) return res.status(401).json({ error: 'Connexion requise.' });
      console.warn(`[TRANSITION] appel sans jeton : ${req.method} ${req.path}`);
      return next();
    }
    if (!roles.includes(req.auth.role)) return res.status(403).json({ error: 'Accès refusé.' });
    // Protection CSRF : une action de modification par cookie doit venir d'un site autorisé.
    if (req.viaCookie && !['GET', 'HEAD', 'OPTIONS'].includes(req.method)) {
      const o = req.headers.origin;
      if (!o || !ORIGINES.includes(o)) return res.status(403).json({ error: 'Origine non autorisée.' });
    }
    next();
  };
}

// Le restaurant connecté a-t-il le droit de toucher à ce restaurant ?
function autorise(req, restaurantId) {
  if (!req.auth) return !AUTH_STRICT; // transition uniquement
  if (req.auth.role === 'admin') return true;
  return req.auth.restaurant_id === restaurantId;
}

/* ───────────────────────── Application ───────────────────────── */
const app = express();
app.set('trust proxy', 1);
app.disable('x-powered-by');
app.use(
  cors(
    ORIGINES.length
      ? {
          origin: (origin, cb) => cb(null, !origin || ORIGINES.includes(origin)),
          credentials: true,
          methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
          allowedHeaders: ['Content-Type', 'Authorization'],
        }
      : undefined
  )
);
app.use((req, res, next) => {
  res.set({ 'X-Content-Type-Options': 'nosniff', 'X-Frame-Options': 'DENY', 'Referrer-Policy': 'no-referrer' });
  next();
});
app.use(express.json({ limit: '100kb' }));
app.use(authentifier);

app.get('/', (req, res) => {
  res.json({ message: '🍽️ Launge Backend fonctionne !' });
});

/* ───────────────────────── Session ───────────────────────── */
app.post('/api/auth/deconnexion', (req, res) => {
  res.clearCookie(NOM_COOKIE, OPTIONS_COOKIE);
  res.json({ message: 'Déconnecté.' });
});

// Permet au site de retrouver la session après un rechargement de page.
app.get('/api/auth/moi', exiger(['restaurant', 'cuisine', 'admin'], { toujours: true }), async (req, res) => {
  const a = req.auth;
  const base = { role: a.role, restaurant_id: a.restaurant_id || null };
  if (a.role === 'restaurant') {
    const { data, error } = await supabase.from('restaurants').select('*').eq('id', a.restaurant_id).maybeSingle();
    if (error) return echec(res, 'moi', error);
    if (!data) return res.status(401).json({ error: 'Session invalide.' });
    return res.json({ ...base, restaurant: nettoyerResto(data) });
  }
  res.json(base);
});

/* ───────────────────────── Restaurants : comptes ───────────────────────── */
app.post('/api/restaurants/inscription', limiter('inscription', 10, 3600000, parIp), async (req, res) => {
  const b = req.body || {};
  const nom = texte(b.nom, 100);
  const ville = texte(b.ville, 100);
  const telephone = texte(b.telephone, 30);
  const adresse = texte(b.adresse, 200) || null;
  const email = texte(b.email, 150).toLowerCase();
  const mdp = typeof b.mot_de_passe === 'string' ? b.mot_de_passe : '';
  if (!nom || !ville) return res.status(400).json({ error: 'Le nom et la ville sont obligatoires.' });
  if (!emailValide(email)) return res.status(400).json({ error: 'Adresse email invalide.' });
  if (mdp.length < 8 || mdp.length > 128) return res.status(400).json({ error: 'Le mot de passe doit contenir au moins 8 caractères.' });

  const { data: existant, error: e1 } = await chercherParEmail('restaurants', email);
  if (e1) return echec(res, 'inscription/email', e1);
  if (existant) return res.status(409).json({ error: 'Cet email est déjà utilisé.' });

  let code_unique = null;
  for (let i = 0; i < 5 && !code_unique; i++) {
    const essai = 'LNG-' + crypto.randomBytes(3).toString('hex').toUpperCase();
    const { data: pris } = await supabase.from('restaurants').select('id').eq('code_unique', essai).maybeSingle();
    if (!pris) code_unique = essai;
  }
  if (!code_unique) return echec(res, 'inscription/code', 'code unique introuvable');

  const hash = await bcrypt.hash(mdp, 10);
  const { data, error } = await supabase
    .from('restaurants')
    .insert([{ nom, ville, adresse, telephone, email, mot_de_passe: hash, code_unique }])
    .select()
    .single();
  if (error) return echec(res, 'inscription', error);
  res.json({ message: 'Restaurant créé !', code_unique, restaurant: nettoyerResto(data) });
});

app.post('/api/restaurants/connexion', limiter('login-ip', 200, 900000, parIp), limiter('login-email', 10, 900000, parEmail), async (req, res) => {
  const b = req.body || {};
  const email = texte(b.email, 150).toLowerCase();
  const mdp = typeof b.mot_de_passe === 'string' ? b.mot_de_passe.slice(0, 128) : '';
  const { data, error } = await chercherParEmail('restaurants', email);
  if (error) return echec(res, 'connexion', error);
  let valide = false;
  try { valide = await bcrypt.compare(mdp, data ? data.mot_de_passe : HASH_FACTICE); } catch { valide = false; }
  if (!data || !valide) return res.status(400).json({ error: 'Email ou mot de passe incorrect.' });
  if (data.statut === 'en_attente') return res.status(403).json({ error: "Votre compte est en attente de validation par l'administrateur." });
  if (data.statut === 'refuse') return res.status(403).json({ error: 'Votre inscription a été refusée.' });
  const token = ouvrirSession(res, { id: data.id, role: 'restaurant', restaurant_id: data.id, nom: data.nom });
  res.json({ token, restaurant: nettoyerResto(data) });
});

app.post('/api/restaurants/connexion-cuisine', limiter('cuisine-ip', 200, 900000, parIp), limiter('cuisine-code', 10, 900000, (req) => texte(req.body && req.body.code_unique, 30) || 'vide'), async (req, res) => {
  const b = req.body || {};
  const code_unique = texte(b.code_unique, 30);
  const code_cuisine = typeof b.code_cuisine === 'string' ? b.code_cuisine.slice(0, 50) : '';
  const { data, error } = await supabase
    .from('restaurants')
    .select('id, nom, code_unique, code_cuisine, statut')
    .eq('code_unique', code_unique)
    .maybeSingle();
  if (error) return echec(res, 'cuisine', error);
  if (!data || !data.code_cuisine || !egal(data.code_cuisine, code_cuisine)) {
    return res.status(400).json({ error: 'Code restaurant ou code cuisine incorrect.' });
  }
  if (STATUTS_BLOQUES.includes(data.statut)) return res.status(403).json({ error: "Ce restaurant n'est pas encore actif." });
  const token = ouvrirSession(res, { id: data.id, role: 'cuisine', restaurant_id: data.id, nom: data.nom });
  res.json({ token, restaurant: { id: data.id, nom: data.nom, code_unique: data.code_unique } });
});

/* ───────────────────────── Restaurants : lecture publique ───────────────────────── */
app.get('/api/restaurants', async (req, res) => {
  const { data, error } = await supabase.from('restaurants').select('id, nom, ville, adresse, image_url').eq('statut', 'valide').order('nom');
  if (error) return echec(res, 'liste restaurants', error);
  res.json(data);
});

app.get('/api/restaurants/code/:code_unique', async (req, res) => {
  const code = texte(req.params.code_unique, 30);
  const { data, error } = await supabase.from('restaurants').select('id, nom, code_unique, recrutement, statut').eq('code_unique', code).maybeSingle();
  if (error) return echec(res, 'restaurant par code', error);
  if (!data || STATUTS_BLOQUES.includes(data.statut)) return res.status(404).json({ error: 'Restaurant introuvable.' });
  const { statut, ...publicData } = data;
  res.json(publicData);
});

app.get('/api/restaurants/:id/info', validerUuid('id'), async (req, res) => {
  const { data, error } = await supabase.from('restaurants').select('id, nom, ville, adresse, image_url, recrutement, statut').eq('id', req.params.id).maybeSingle();
  if (error) return echec(res, 'info restaurant', error);
  if (!data || STATUTS_BLOQUES.includes(data.statut)) return res.status(404).json({ error: 'Restaurant introuvable.' });
  const { statut, ...publicData } = data;
  res.json(publicData);
});
/* ───────────────────────── Restaurants : réglages ───────────────────────── */
// Profil public du restaurant (adresse et photo affichées dans la liste des restaurants).
app.put('/api/restaurants/:id/profil', validerUuid('id'), exiger(['restaurant', 'admin']), async (req, res) => {
  if (!autorise(req, req.params.id)) return res.status(403).json({ error: 'Accès refusé.' });
  const b = req.body || {};
  const maj = {};
  if (b.adresse !== undefined) maj.adresse = texte(b.adresse, 200) || null;
  if (b.image_url !== undefined) {
    if (b.image_url === null || b.image_url === '') maj.image_url = null;
    // La photo doit venir de NOTRE stockage et du dossier de CE restaurant (pas de lien externe ni de photo d'un autre).
    else if (typeof b.image_url === 'string' && b.image_url.length <= 500 && b.image_url.startsWith(`${PREFIXE_IMAGES}${req.params.id}/`)) maj.image_url = b.image_url;
    else return res.status(400).json({ error: 'Image invalide.' });
  }
  if (!Object.keys(maj).length) return res.status(400).json({ error: 'Rien à modifier.' });
  const { data, error } = await supabase.from('restaurants').update(maj).eq('id', req.params.id).select('id, nom, ville, adresse, image_url').maybeSingle();
  if (error) return echec(res, 'profil restaurant', error);
  if (!data) return res.status(404).json({ error: 'Restaurant introuvable.' });
  res.json(data);
});
app.put('/api/restaurants/:id/recrutement', validerUuid('id'), exiger(['restaurant', 'admin']), async (req, res) => {
  if (!autorise(req, req.params.id)) return res.status(403).json({ error: 'Accès refusé.' });
  const recrutement = req.body && req.body.recrutement;
  if (recrutement === undefined || JSON.stringify(recrutement).length > 20000) return res.status(400).json({ error: 'Données de recrutement invalides.' });
  const { data, error } = await supabase.from('restaurants').update({ recrutement }).eq('id', req.params.id).select().maybeSingle();
  if (error) return echec(res, 'recrutement', error);
  if (!data) return res.status(404).json({ error: 'Restaurant introuvable.' });
  res.json(nettoyerResto(data));
});

app.put('/api/restaurants/:id/code-cuisine', validerUuid('id'), exiger(['restaurant', 'admin']), async (req, res) => {
  if (!autorise(req, req.params.id)) return res.status(403).json({ error: 'Accès refusé.' });
  const code = texte(req.body && req.body.code_cuisine, 20);
  if (code.length < 4) return res.status(400).json({ error: 'Le code cuisine doit contenir au moins 4 caractères.' });
  const { data, error } = await supabase.from('restaurants').update({ code_cuisine: code }).eq('id', req.params.id).select().maybeSingle();
  if (error) return echec(res, 'code cuisine', error);
  if (!data) return res.status(404).json({ error: 'Restaurant introuvable.' });
  res.json(nettoyerResto(data));
});

/* ───────────────────────── Administration ───────────────────────── */
app.post('/api/admin/connexion', limiter('admin-ip', 100, 900000, parIp), limiter('admin-email', 5, 900000, parEmail), async (req, res) => {
  const b = req.body || {};
  const email = texte(b.email, 150).toLowerCase();
  const mdp = typeof b.mot_de_passe === 'string' ? b.mot_de_passe.slice(0, 128) : '';
  const { data, error } = await chercherParEmail('admins', email);
  if (error) return echec(res, 'admin connexion', error);
  let valide = false;
  try { valide = await bcrypt.compare(mdp, data ? data.mot_de_passe : HASH_FACTICE); } catch { valide = false; }
  if (!data || !valide) return res.status(400).json({ error: 'Email ou mot de passe incorrect.' });
  const token = ouvrirSession(res, { id: data.id, role: 'admin' });
  res.json({ token });
});

// Journal des actions de l'administrateur (qui a fait quoi). Il ne bloque jamais l'action elle-même.
async function journaliser(req, action, cible) {
  try {
    const { error } = await supabase.from('journal_admin').insert([{ admin_id: (req.auth && req.auth.id) || null, action, cible_id: cible.id, cible_nom: cible.nom || null }]);
    if (error) console.error('[JOURNAL] écriture impossible :', error.message);
  } catch (e) { console.error('[JOURNAL] écriture impossible :', e.message); }
}

app.get('/api/admin/restaurants', exiger(['admin']), async (req, res) => {
  const { data, error } = await supabase
    .from('restaurants')
    .select('id, nom, ville, adresse, image_url, code_unique, telephone, email, statut, created_at')
    .order('created_at', { ascending: false });
  if (error) return echec(res, 'admin liste', error);
  res.json(data);
});

for (const [action, statut] of [['valider', 'valide'], ['refuser', 'refuse']]) {
  app.put(`/api/admin/restaurants/:id/${action}`, validerUuid('id'), exiger(['admin']), async (req, res) => {
    const { data, error } = await supabase.from('restaurants').update({ statut }).eq('id', req.params.id).select().maybeSingle();
    if (error) return echec(res, `admin ${action}`, error);
    if (!data) return res.status(404).json({ error: 'Restaurant introuvable.' });
    await journaliser(req, action, data);
    res.json(nettoyerResto(data));
  });
}

app.delete('/api/admin/restaurants/:id', validerUuid('id'), exiger(['admin']), async (req, res) => {
  const id = req.params.id;
  const { data: resto, error: e0 } = await supabase.from('restaurants').select('id, nom').eq('id', id).maybeSingle();
  if (e0) return echec(res, 'suppression lecture', e0);
  if (!resto) return res.status(404).json({ error: 'Restaurant introuvable.' });
  const r1 = await supabase.from('menus').delete().eq('restaurant_id', id);
  if (r1.error) return echec(res, 'suppression menus', r1.error);
  const r2 = await supabase.from('commandes').delete().eq('restaurant_id', id);
  if (r2.error) return echec(res, 'suppression commandes', r2.error);
  const r3 = await supabase.from('restaurants').delete().eq('id', id);
  if (r3.error) return echec(res, 'suppression restaurant', r3.error);
  await journaliser(req, 'supprimer', resto);
  try {
    const { data: fichiers } = await supabase.storage.from(BUCKET).list(id);
    if (fichiers && fichiers.length) await supabase.storage.from(BUCKET).remove(fichiers.map((f) => `${id}/${f.name}`));
  } catch { /* le nettoyage des photos est facultatif */ }
  res.json({ message: 'Restaurant supprimé' });
});

app.get('/api/admin/journal', exiger(['admin']), async (req, res) => {
  const { data, error } = await supabase
    .from('journal_admin')
    .select('id, action, cible_id, cible_nom, created_at')
    .order('created_at', { ascending: false })
    .limit(60);
  if (error) return echec(res, 'admin journal', error);
  res.json(data);
});
/* ───────────────────────── Menu ───────────────────────── */
function champsPlat(b, creation) {
  const maj = {};
  const erreurs = [];
  const nombre = (cle, max) => {
    const v = b[cle];
    if (v === undefined || v === null || v === '') return;
    const n = entier(v, 0, max);
    if (n === null) erreurs.push(cle);
    else maj[cle] = n;
  };
  if (b.nom !== undefined) {
    const nom = texte(b.nom, 120);
    if (!nom) erreurs.push('nom');
    else maj.nom = nom;
  }
  nombre('prix', 10000000);
  nombre('stock', 1000000);
  nombre('seuil_alerte', 1000000);
  if (b.categorie !== undefined && b.categorie !== null) maj.categorie = texte(b.categorie, 60) || 'Plats';
  if (b.emoji !== undefined && b.emoji !== null) maj.emoji = texte(b.emoji, 16);
  if (b.disponible !== undefined && b.disponible !== null) {
    if (typeof b.disponible === 'boolean') maj.disponible = b.disponible;
    else erreurs.push('disponible');
  }
  if (b.image_url !== undefined) {
    if (b.image_url === null || b.image_url === '') maj.image_url = null;
    else if (typeof b.image_url === 'string' && b.image_url.length <= 500 && b.image_url.startsWith(PREFIXE_IMAGES)) maj.image_url = b.image_url;
    else erreurs.push('image_url');
  }
  if (creation) {
    if (maj.nom === undefined) erreurs.push('nom');
    if (maj.prix === undefined) erreurs.push('prix');
  }
  return { maj, erreurs };
}

app.get('/api/menu/:restaurant_id', validerUuid('restaurant_id'), async (req, res) => {
  const { data, error } = await supabase.from('menus').select('*').eq('restaurant_id', req.params.restaurant_id).order('created_at', { ascending: true });
  if (error) return echec(res, 'menu', error);
  res.json(data);
});

app.post('/api/menu', exiger(['restaurant', 'admin']), async (req, res) => {
  const b = req.body || {};
  if (!estUuid(b.restaurant_id)) return res.status(400).json({ error: 'Restaurant invalide.' });
  if (!autorise(req, b.restaurant_id)) return res.status(403).json({ error: 'Accès refusé.' });
  const { maj, erreurs } = champsPlat(b, true);
  if (erreurs.length) return res.status(400).json({ error: `Champs invalides : ${erreurs.join(', ')}.` });
  const { data, error } = await supabase.from('menus').insert([{ restaurant_id: b.restaurant_id, ...maj }]).select().single();
  if (error) return echec(res, 'ajout plat', error);
  res.json(data);
});

// Chargement d'un plat + vérification que l'utilisateur a le droit d'y toucher.
async function platAutorise(req, res) {
  const { data, error } = await supabase.from('menus').select('id, restaurant_id').eq('id', req.params.id).maybeSingle();
  if (error) { echec(res, 'lecture plat', error); return null; }
  if (!data) { res.status(404).json({ error: 'Plat introuvable.' }); return null; }
  if (!autorise(req, data.restaurant_id)) { res.status(403).json({ error: 'Accès refusé.' }); return null; }
  return data;
}

app.put('/api/menu/:id', validerUuid('id'), exiger(['restaurant', 'admin']), async (req, res) => {
  const plat = await platAutorise(req, res);
  if (!plat) return;
  const { maj, erreurs } = champsPlat(req.body || {}, false);
  if (erreurs.length) return res.status(400).json({ error: `Champs invalides : ${erreurs.join(', ')}.` });
  delete maj.stock; // le stock ne se modifie que par les routes de stock (sinon enregistrer le formulaire d'un plat écraserait les ventes en cours)
  if (!Object.keys(maj).length) return res.status(400).json({ error: 'Aucune modification.' });
  const { data, error } = await supabase.from('menus').update(maj).eq('id', plat.id).select().single();
  if (error) return echec(res, 'modification plat', error);
  res.json(data);
});

app.delete('/api/menu/:id', validerUuid('id'), exiger(['restaurant', 'admin']), async (req, res) => {
  const plat = await platAutorise(req, res);
  if (!plat) return;
  const { error } = await supabase.from('menus').delete().eq('id', plat.id);
  if (error) return echec(res, 'suppression plat', error);
  res.json({ message: 'Plat supprimé' });
});

// Traduit les erreurs « métier » renvoyées par la base en réponses claires.
function erreurStock(res, ctx, err) {
  const msg = (err && err.message) || '';
  if (/PLAT_INTROUVABLE/.test(msg)) return res.status(404).json({ error: 'Plat introuvable.' });
  if (/STOCK_INVALIDE|COMPTE_INVALIDE/.test(msg)) return res.status(400).json({ error: 'Quantité invalide.' });
  if (/INVENTAIRE_VIDE/.test(msg)) return res.status(400).json({ error: "Renseignez au moins un plat pour l'inventaire." });
  if (/INVENTAIRE_DOUBLON/.test(msg)) return res.status(400).json({ error: 'Un plat est compté deux fois.' });
  return echec(res, ctx, err);
}

// Correction : on fixe une quantité exacte (l'écart est enregistré dans l'historique).
app.put('/api/stock/:id', validerUuid('id'), exiger(['restaurant', 'admin']), async (req, res) => {
  const plat = await platAutorise(req, res);
  if (!plat) return;
  const stock = entier(req.body && req.body.stock, 0, 1000000);
  if (stock === null) return res.status(400).json({ error: 'Stock invalide.' });
  const { error } = await supabase.rpc('fixer_stock', { p_plat: plat.id, p_restaurant: plat.restaurant_id, p_stock: stock });
  if (error) return erreurStock(res, 'stock', error);
  const { data, error: e2 } = await supabase.from('menus').select('*').eq('id', plat.id).single();
  if (e2) return echec(res, 'stock/lecture', e2);
  res.json(data);
});

// Réception de marchandise (+) ou retrait (-) : la variation est appliquée de façon atomique.
app.post('/api/stock/:id/ajuster', validerUuid('id'), exiger(['restaurant', 'admin']), async (req, res) => {
  const plat = await platAutorise(req, res);
  if (!plat) return;
  const delta = entier(req.body && req.body.delta, -1000000, 1000000);
  if (delta === null || delta === 0) return res.status(400).json({ error: 'Quantité invalide.' });
  const motif = delta > 0 ? 'reapprovisionnement' : 'correction';
  const { error } = await supabase.rpc('ajuster_stock', { p_plat: plat.id, p_restaurant: plat.restaurant_id, p_delta: delta, p_motif: motif });
  if (error) return erreurStock(res, 'stock/ajuster', error);
  const { data, error: e2 } = await supabase.from('menus').select('*').eq('id', plat.id).single();
  if (e2) return echec(res, 'stock/lecture', e2);
  res.json(data);
});

// Historique des mouvements de stock (commandes, réceptions, corrections, inventaires).
app.get('/api/stock/:restaurant_id/mouvements', validerUuid('restaurant_id'), exiger(['restaurant', 'admin']), async (req, res) => {
  if (!autorise(req, req.params.restaurant_id)) return res.status(403).json({ error: 'Accès refusé.' });
  const { data, error } = await supabase
    .from('mouvements_stock')
    .select('id, plat_id, plat_nom, delta, stock_apres, motif, created_at')
    .eq('restaurant_id', req.params.restaurant_id)
    .order('created_at', { ascending: false })
    .limit(100);
  if (error) return echec(res, 'mouvements', error);
  res.json(data);
});

/* ───────────────────────── Inventaires ───────────────────────── */
app.post('/api/inventaires/:restaurant_id', validerUuid('restaurant_id'), exiger(['restaurant', 'admin']), async (req, res) => {
  if (!autorise(req, req.params.restaurant_id)) return res.status(403).json({ error: 'Accès refusé.' });
  const brut = req.body && req.body.lignes;
  if (!Array.isArray(brut) || brut.length < 1 || brut.length > 500) return res.status(400).json({ error: "Renseignez au moins un plat pour l'inventaire." });
  const lignes = [];
  for (const l of brut) {
    const compte = entier(l && l.compte, 0, 1000000);
    if (!l || !estUuid(l.plat_id) || compte === null) return res.status(400).json({ error: 'Quantité invalide.' });
    lignes.push({ plat_id: l.plat_id, compte });
  }
  const { data: id, error } = await supabase.rpc('valider_inventaire', { p_restaurant: req.params.restaurant_id, p_lignes: lignes });
  if (error) return erreurStock(res, 'inventaire', error);
  const { data, error: e2 } = await supabase.from('inventaires').select('id, nb_plats, nb_ecarts, valeur_ecart, created_at').eq('id', id).single();
  if (e2) return echec(res, 'inventaire/lecture', e2);
  res.json(data);
});

app.get('/api/inventaires/:restaurant_id', validerUuid('restaurant_id'), exiger(['restaurant', 'admin']), async (req, res) => {
  if (!autorise(req, req.params.restaurant_id)) return res.status(403).json({ error: 'Accès refusé.' });
  const { data, error } = await supabase
    .from('inventaires')
    .select('id, nb_plats, nb_ecarts, valeur_ecart, created_at')
    .eq('restaurant_id', req.params.restaurant_id)
    .order('created_at', { ascending: false })
    .limit(30);
  if (error) return echec(res, 'liste inventaires', error);
  res.json(data);
});

app.get('/api/inventaires/:restaurant_id/:id', validerUuid('restaurant_id'), validerUuid('id'), exiger(['restaurant', 'admin']), async (req, res) => {
  if (!autorise(req, req.params.restaurant_id)) return res.status(403).json({ error: 'Accès refusé.' });
  const { data: inv, error } = await supabase.from('inventaires').select('id, nb_plats, nb_ecarts, valeur_ecart, created_at').eq('id', req.params.id).eq('restaurant_id', req.params.restaurant_id).maybeSingle();
  if (error) return echec(res, 'inventaire', error);
  if (!inv) return res.status(404).json({ error: 'Inventaire introuvable.' });
  const { data: lignes, error: e2 } = await supabase.from('inventaire_lignes').select('plat_id, plat_nom, prix, theorique, compte, ecart').eq('inventaire_id', inv.id).order('plat_nom');
  if (e2) return echec(res, 'inventaire/lignes', e2);
  res.json({ ...inv, lignes });
});

/* ───────────────────────── Photos des plats ───────────────────────── */
function typeImage(buf) {
  if (buf.length > 3 && buf[0] === 0xff && buf[1] === 0xd8 && buf[2] === 0xff) return { ext: 'jpg', mime: 'image/jpeg' };
  if (buf.length > 8 && buf.subarray(0, 8).equals(Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]))) return { ext: 'png', mime: 'image/png' };
  if (buf.length > 12 && buf.subarray(0, 4).toString('ascii') === 'RIFF' && buf.subarray(8, 12).toString('ascii') === 'WEBP') return { ext: 'webp', mime: 'image/webp' };
  return null;
}

// Le site envoie le fichier brut : Content-Type = image/jpeg | image/png | image/webp
app.post(
  '/api/menu/image',
  exiger(['restaurant', 'admin'], { toujours: true }),
  limiter('upload', 60, 3600000, (req) => (req.auth && req.auth.id) || 'x'),
  express.raw({ type: ['image/jpeg', 'image/png', 'image/webp'], limit: '5mb' }),
  async (req, res) => {
    const restaurantId = req.auth.role === 'admin' ? req.query.restaurant_id : req.auth.restaurant_id;
    if (!estUuid(restaurantId)) return res.status(400).json({ error: 'Restaurant invalide.' });
    if (!Buffer.isBuffer(req.body) || !req.body.length) return res.status(400).json({ error: 'Image invalide (JPEG, PNG ou WebP, 5 Mo maximum).' });
    const type = typeImage(req.body);
    if (!type) return res.status(400).json({ error: "Ce fichier n'est pas une image valide." });
    const chemin = `${restaurantId}/${Date.now()}-${crypto.randomBytes(6).toString('hex')}.${type.ext}`;
    const { error } = await supabase.storage.from(BUCKET).upload(chemin, req.body, { contentType: type.mime, upsert: false, cacheControl: '31536000' });
    if (error) return echec(res, 'upload image', error);
    res.json({ url: supabase.storage.from(BUCKET).getPublicUrl(chemin).data.publicUrl });
  }
);

// Outils des promotions : lecture du code, messages d'erreur clairs, numéro de téléphone.
const CODE_PROMO = /^[A-Z0-9_-]{3,20}$/;
const lireCode = (v) => (typeof v === 'string' ? v.trim().toUpperCase().slice(0, 30) : '');
const chiffresTel = (v) => { const t = String(v == null ? '' : v).replace(/\D/g, ''); return t.length >= 8 && t.length <= 15 ? t : null; };
function erreurPromo(res, ctx, err) {
  const msg = (err && err.message) || '';
  if (/PROMO_INVALIDE/.test(msg)) return res.status(400).json({ error: "Ce code promo n'est pas valable." });
  if (/PROMO_EXPIREE/.test(msg)) return res.status(400).json({ error: 'Ce code promo a expiré.' });
  if (/PROMO_EPUISEE/.test(msg)) return res.status(400).json({ error: "Ce code promo n'est plus disponible." });
  const m = /PROMO_MINIMUM:(\d+)/.exec(msg);
  if (m) return res.status(400).json({ error: `Ce code est valable à partir de ${Number(m[1]).toLocaleString('fr-FR')} FCFA de commande.` });
  return echec(res, ctx, err);
}

/* ───────────────────────── Commandes ───────────────────────── */
// Route publique : un client peut commander sans compte. Le total (et la remise) sont recalculés ici.
app.post('/api/commandes', limiter('commande', 300, 600000, parIp), async (req, res) => {
  const b = req.body || {};
  if (!estUuid(b.restaurant_id)) return res.status(400).json({ error: 'Restaurant invalide.' });
  if (!Array.isArray(b.items) || b.items.length < 1 || b.items.length > 50) return res.status(400).json({ error: 'Panier invalide.' });

  const quantites = new Map();
  for (const it of b.items) {
    const qte = entier(it && it.qte, 1, 99);
    if (!it || !estUuid(it.id) || qte === null) return res.status(400).json({ error: 'Panier invalide.' });
    quantites.set(it.id, (quantites.get(it.id) || 0) + qte);
  }

  const { data: resto, error: e1 } = await supabase.from('restaurants').select('id, statut').eq('id', b.restaurant_id).maybeSingle();
  if (e1) return echec(res, 'commande/restaurant', e1);
  if (!resto) return res.status(404).json({ error: 'Restaurant introuvable.' });
  if (STATUTS_BLOQUES.includes(resto.statut)) return res.status(403).json({ error: "Ce restaurant n'accepte pas de commandes." });

  const { data: plats, error: e2 } = await supabase
    .from('menus')
    .select('id, nom, prix, stock, disponible')
    .eq('restaurant_id', b.restaurant_id)
    .in('id', [...quantites.keys()]);
  if (e2) return echec(res, 'commande/menu', e2);

  const items = [];
  let total = 0;
  for (const [id, qte] of quantites) {
    const plat = (plats || []).find((p) => p.id === id);
    if (!plat) return res.status(400).json({ error: "Un des plats n'existe plus." });
    if (plat.disponible === false) return res.status(400).json({ error: `${plat.nom} n'est plus disponible.` });
    if (typeof plat.stock === 'number' && qte > plat.stock) return res.status(400).json({ error: `Stock insuffisant pour ${plat.nom}.` });
    items.push({ id, nom: plat.nom, qte, prix: plat.prix });
    total += plat.prix * qte;
  }

  // Code promo : première lecture sans rien consommer, pour répondre clairement avant de toucher au stock.
  const code = lireCode(b.code_promo);
  let remise = 0;
  if (code) {
    if (!CODE_PROMO.test(code)) return res.status(400).json({ error: "Ce code promo n'est pas valable." });
    const { data: ev, error: eP } = await supabase.rpc('evaluer_promo', { p_restaurant: b.restaurant_id, p_code: code, p_total: total, p_consommer: false });
    if (eP) return erreurPromo(res, 'commande/promo', eP);
    remise = ev.remise;
  }

  // Le numéro de téléphone n'est gardé que si le restaurant a activé la fidélité.
  const { data: fid } = await supabase.from('fidelite_config').select('actif').eq('restaurant_id', b.restaurant_id).maybeSingle();
  const telephone = fid && fid.actif ? chiffresTel(b.telephone) : null;

  // Décompte automatique du stock : tout ou rien, et jamais sous zéro (même si deux clients commandent en même temps).
  const correlation = crypto.randomUUID();
  const lignes = items.map((i) => ({ id: i.id, qte: i.qte }));
  const { error: eStock } = await supabase.rpc('decompter_stock', { p_restaurant: b.restaurant_id, p_items: lignes, p_commande: correlation });
  if (eStock) {
    const m = /STOCK_INSUFFISANT:(.*)/.exec(eStock.message || '');
    if (m) return res.status(400).json({ error: `Stock insuffisant pour ${m[1].trim()}.` });
    if (/PLAT_INTROUVABLE/.test(eStock.message || '')) return res.status(400).json({ error: "Un des plats n'existe plus." });
    return echec(res, 'commande/stock', eStock);
  }
  const rendreStock = async () => {
    const { error: eR } = await supabase.rpc('restituer_stock', { p_restaurant: b.restaurant_id, p_items: lignes, p_commande: correlation });
    if (eR) console.error('[STOCK] restitution impossible :', eR.message);
  };

  // Seconde lecture, cette fois en comptant l'utilisation (verrou : une limite d'usage n'est jamais dépassée).
  let promoId = null;
  if (code) {
    const { data: ev2, error: eP2 } = await supabase.rpc('evaluer_promo', { p_restaurant: b.restaurant_id, p_code: code, p_total: total, p_consommer: true });
    if (eP2) { await rendreStock(); return erreurPromo(res, 'commande/promo2', eP2); }
    promoId = ev2.id; remise = ev2.remise;
  }

  const { data, error } = await supabase
    .from('commandes')
    .insert([{ restaurant_id: b.restaurant_id, numero_table: texte(b.numero_table, 20), items, total: total - remise, remise, code_promo: code || null, telephone, mode_paiement: texte(b.mode_paiement, 30), statut: 'en_cours' }])
    .select()
    .single();
  if (error) {
    // La commande n'a pas pu être enregistrée : on remet les plats en stock et on rend le code promo.
    await rendreStock();
    if (promoId) { const { error: eRp } = await supabase.rpc('rendre_promo', { p_id: promoId }); if (eRp) console.error('[PROMO] restitution impossible :', eRp.message); }
    return echec(res, 'commande', error);
  }
  // On rattache les mouvements de stock à la commande créée (facultatif : l'historique reste correct sans).
  const { error: eLien } = await supabase.from('mouvements_stock').update({ commande_id: data.id }).eq('commande_id', correlation);
  if (eLien) console.error('[STOCK] lien commande impossible :', eLien.message);
  res.json(data);
});
app.get('/api/commandes/:restaurant_id', validerUuid('restaurant_id'), exiger(['restaurant', 'cuisine', 'admin']), async (req, res) => {
  if (!autorise(req, req.params.restaurant_id)) return res.status(403).json({ error: 'Accès refusé.' });
  const { data, error } = await supabase
    .from('commandes')
    .select('*')
    .eq('restaurant_id', req.params.restaurant_id)
    .order('created_at', { ascending: false })
    .limit(1000);
  if (error) return echec(res, 'liste commandes', error);
  res.json(data);
});
// Suivi public d'une commande : la référence secrète (128 bits) fait office de clé, aucun compte nécessaire.
// Ne renvoie que le strict nécessaire : jamais d'identifiant interne ni d'information sur d'autres commandes.
const REF_SUIVI = /^[A-Za-z0-9_-]{16,64}$/;
app.get('/api/suivi/:reference',
  limiter('suivi-ip', 1500, 600000, parIp),
  limiter('suivi-ref', 400, 600000, (req) => String(req.params.reference).slice(0, 64)),
  async (req, res) => {
    res.set('Cache-Control', 'no-store');
    const ref = req.params.reference;
    if (!REF_SUIVI.test(ref)) return res.status(404).json({ error: 'Commande introuvable.' });
    const { data: cmd, error } = await supabase
      .from('commandes')
      .select('id, restaurant_id, numero_table, items, total, statut, mode_paiement, created_at, remise, code_promo, telephone, recompense_code, fidelite_traitee')
      .eq('reference_suivi', ref)
      .maybeSingle();
    if (error) return echec(res, 'suivi', error);
    if (!cmd) return res.status(404).json({ error: 'Commande introuvable.' });
    const { data: resto } = await supabase.from('restaurants').select('nom').eq('id', cmd.restaurant_id).maybeSingle();
    const { data: avis } = await supabase.from('avis').select('note, commentaire').eq('commande_id', cmd.id).maybeSingle();
    res.json({
      statut: cmd.statut,
      numero_table: cmd.numero_table,
      total: cmd.total,
      remise: cmd.remise || 0,
      code_promo: cmd.code_promo || null,
      mode_paiement: cmd.mode_paiement,
      created_at: cmd.created_at,
      items: (Array.isArray(cmd.items) ? cmd.items : []).map((i) => ({ nom: i.nom, qte: i.qte, prix: i.prix })),
      restaurant: resto ? resto.nom : null,
      recompense_code: cmd.recompense_code || null,
      fidelite_attente: Boolean(cmd.telephone) && !cmd.fidelite_traitee,
      avis: avis || null,
    });
  }
);

// Avis du client : une seule fois par commande, uniquement une fois la commande servie.
app.post('/api/suivi/:reference/avis', limiter('avis-ip', 30, 3600000, parIp), async (req, res) => {
  const ref = req.params.reference;
  if (!REF_SUIVI.test(ref)) return res.status(404).json({ error: 'Commande introuvable.' });
  const note = entier(req.body && req.body.note, 1, 5);
  if (note === null) return res.status(400).json({ error: 'Choisissez une note de 1 à 5.' });
  const commentaire = texte(req.body && req.body.commentaire, 600) || null;
  const { data: cmd, error: e1 } = await supabase.from('commandes').select('id, restaurant_id, statut').eq('reference_suivi', ref).maybeSingle();
  if (e1) return echec(res, 'avis/commande', e1);
  if (!cmd) return res.status(404).json({ error: 'Commande introuvable.' });
  if (cmd.statut !== 'servi') return res.status(409).json({ error: 'Vous pourrez donner votre avis une fois la commande servie.' });
  const { error } = await supabase.from('avis').insert([{ restaurant_id: cmd.restaurant_id, commande_id: cmd.id, note, commentaire }]);
  if (error) {
    if (error.code === '23505') return res.status(409).json({ error: 'Vous avez déjà donné votre avis sur cette commande.' });
    return echec(res, 'avis/insert', error);
  }
  res.json({ note, commentaire });
});

// Nouvelle route : changement de statut vérifié par le serveur (en_cours → pret → servi).
const TRANSITIONS = { en_cours: ['acceptee', 'pret'], acceptee: ['pret'], pret: ['servi'] };
app.put('/api/commandes/:id/statut', validerUuid('id'), exiger(['restaurant', 'cuisine', 'admin'], { toujours: true }), async (req, res) => {
  const nouveau = texte(req.body && req.body.statut, 20);
  const { data: cmd, error: e1 } = await supabase.from('commandes').select('id, restaurant_id, statut').eq('id', req.params.id).maybeSingle();
  if (e1) return echec(res, 'statut/lecture', e1);
  if (!cmd) return res.status(404).json({ error: 'Commande introuvable.' });
  if (!autorise(req, cmd.restaurant_id)) return res.status(403).json({ error: 'Accès refusé.' });
  if (cmd.statut === nouveau) return res.json(cmd);
  if (!Object.hasOwn(TRANSITIONS, cmd.statut) || !TRANSITIONS[cmd.statut].includes(nouveau)) return res.status(409).json({ error: 'Changement de statut impossible.' });
  const { data, error } = await supabase.from('commandes').update({ statut: nouveau }).eq('id', cmd.id).eq('statut', cmd.statut).select().maybeSingle();
  if (error) return echec(res, 'statut/maj', error);
  if (!data) return res.status(409).json({ error: 'La commande a déjà été modifiée.' });
  // Fidélité : quand la commande est servie, on ajoute les points du client (s'il a donné son numéro).
  if (nouveau === 'servi' && data.telephone && !data.fidelite_traitee) {
    const { data: recompense, error: eF } = await supabase.rpc('crediter_fidelite', { p_restaurant: data.restaurant_id, p_tel: data.telephone, p_montant: data.total });
    if (eF) console.error('[FIDELITE] crédit impossible :', eF.message);
    else {
      const { error: eM } = await supabase.from('commandes').update({ fidelite_traitee: true, recompense_code: recompense || null }).eq('id', data.id);
      if (eM) console.error('[FIDELITE] marquage impossible :', eM.message);
    }
  }
  res.json(data);
});

/* ───────────────────────── Promotions, avis, fidélité ───────────────────────── */
const COLONNES_PROMO = 'id, code, type, valeur, min_commande, debut, fin, max_usages, usages, actif, created_at';
const dateDebut = (s) => (typeof s === 'string' && /^\d{4}-\d{2}-\d{2}$/.test(s) && !isNaN(new Date(`${s}T00:00:00+01:00`)) ? `${s}T00:00:00+01:00` : null);
const dateFin = (s) => (typeof s === 'string' && /^\d{4}-\d{2}-\d{2}$/.test(s) && !isNaN(new Date(`${s}T23:59:59+01:00`)) ? `${s}T23:59:59+01:00` : null);

// Le client vérifie son code avant de payer (aperçu : la commande recalcule tout de son côté).
app.post('/api/promotions/verifier', limiter('promo-ip', 60, 600000, parIp), async (req, res) => {
  const b = req.body || {};
  const code = lireCode(b.code);
  if (!estUuid(b.restaurant_id) || !CODE_PROMO.test(code)) return res.status(400).json({ error: "Ce code promo n'est pas valable." });
  if (!Array.isArray(b.items) || b.items.length < 1 || b.items.length > 50) return res.status(400).json({ error: 'Panier invalide.' });
  const quantites = new Map();
  for (const it of b.items) {
    const qte = entier(it && it.qte, 1, 99);
    if (!it || !estUuid(it.id) || qte === null) return res.status(400).json({ error: 'Panier invalide.' });
    quantites.set(it.id, (quantites.get(it.id) || 0) + qte);
  }
  const { data: plats, error: e1 } = await supabase.from('menus').select('id, prix').eq('restaurant_id', b.restaurant_id).in('id', [...quantites.keys()]);
  if (e1) return echec(res, 'promo/menu', e1);
  let total = 0;
  for (const [id, qte] of quantites) {
    const plat = (plats || []).find((p) => p.id === id);
    if (!plat) return res.status(400).json({ error: "Un des plats n'existe plus." });
    total += plat.prix * qte;
  }
  const { data, error } = await supabase.rpc('evaluer_promo', { p_restaurant: b.restaurant_id, p_code: code, p_total: total, p_consommer: false });
  if (error) return erreurPromo(res, 'promo/verifier', error);
  res.json({ code: data.code, remise: data.remise, total_apres: total - data.remise });
});

app.get('/api/promotions/:restaurant_id', validerUuid('restaurant_id'), exiger(['restaurant', 'admin']), async (req, res) => {
  if (!autorise(req, req.params.restaurant_id)) return res.status(403).json({ error: 'Accès refusé.' });
  const { data, error } = await supabase.from('promotions').select(COLONNES_PROMO).eq('restaurant_id', req.params.restaurant_id).eq('source', 'manuel').order('created_at', { ascending: false }).limit(200);
  if (error) return echec(res, 'liste promos', error);
  res.json(data);
});

app.post('/api/promotions/:restaurant_id', validerUuid('restaurant_id'), exiger(['restaurant', 'admin']), async (req, res) => {
  if (!autorise(req, req.params.restaurant_id)) return res.status(403).json({ error: 'Accès refusé.' });
  const b = req.body || {};
  const code = lireCode(b.code);
  if (!CODE_PROMO.test(code)) return res.status(400).json({ error: 'Le code doit contenir de 3 à 20 lettres, chiffres ou tirets.' });
  const type = b.type === 'montant' ? 'montant' : b.type === 'pourcent' ? 'pourcent' : null;
  if (!type) return res.status(400).json({ error: 'Choisissez le type de réduction.' });
  const valeur = entier(b.valeur, 1, type === 'pourcent' ? 100 : 10000000);
  if (valeur === null) return res.status(400).json({ error: type === 'pourcent' ? 'Le pourcentage doit être entre 1 et 100.' : 'Montant invalide.' });
  const minCommande = b.min_commande === '' || b.min_commande == null ? 0 : entier(b.min_commande, 0, 10000000);
  if (minCommande === null) return res.status(400).json({ error: 'Montant minimum invalide.' });
  const maxUsages = b.max_usages === '' || b.max_usages == null ? null : entier(b.max_usages, 1, 1000000);
  if (b.max_usages !== '' && b.max_usages != null && maxUsages === null) return res.status(400).json({ error: "Limite d'utilisations invalide." });
  const debut = b.debut ? dateDebut(b.debut) : null;
  const fin = b.fin ? dateFin(b.fin) : null;
  if ((b.debut && !debut) || (b.fin && !fin)) return res.status(400).json({ error: 'Date invalide.' });
  if (debut && fin && new Date(fin) < new Date(debut)) return res.status(400).json({ error: 'La date de fin précède la date de début.' });
  const { data, error } = await supabase.from('promotions')
    .insert([{ restaurant_id: req.params.restaurant_id, code, type, valeur, min_commande: minCommande, max_usages: maxUsages, debut, fin }])
    .select(COLONNES_PROMO).single();
  if (error) {
    if (error.code === '23505') return res.status(409).json({ error: 'Ce code existe déjà.' });
    return echec(res, 'créer promo', error);
  }
  res.json(data);
});

app.put('/api/promotions/:restaurant_id/:id', validerUuid('restaurant_id', 'id'), exiger(['restaurant', 'admin']), async (req, res) => {
  if (!autorise(req, req.params.restaurant_id)) return res.status(403).json({ error: 'Accès refusé.' });
  if (typeof (req.body && req.body.actif) !== 'boolean') return res.status(400).json({ error: 'Requête invalide.' });
  const { data, error } = await supabase.from('promotions').update({ actif: req.body.actif })
    .eq('id', req.params.id).eq('restaurant_id', req.params.restaurant_id).eq('source', 'manuel').select(COLONNES_PROMO).maybeSingle();
  if (error) return echec(res, 'maj promo', error);
  if (!data) return res.status(404).json({ error: 'Promotion introuvable.' });
  res.json(data);
});

app.delete('/api/promotions/:restaurant_id/:id', validerUuid('restaurant_id', 'id'), exiger(['restaurant', 'admin']), async (req, res) => {
  if (!autorise(req, req.params.restaurant_id)) return res.status(403).json({ error: 'Accès refusé.' });
  const { error } = await supabase.from('promotions').delete().eq('id', req.params.id).eq('restaurant_id', req.params.restaurant_id).eq('source', 'manuel');
  if (error) return echec(res, 'supprimer promo', error);
  res.json({ ok: true });
});

// Vitrine publique : note moyenne et programme de fidélité (affichés au client).
app.get('/api/restaurants/:id/vitrine', validerUuid('id'), async (req, res) => {
  const { data: notes, error } = await supabase.from('avis').select('note').eq('restaurant_id', req.params.id).limit(5000);
  if (error) return echec(res, 'vitrine/avis', error);
  const { data: fid } = await supabase.from('fidelite_config').select('actif, fcfa_par_point, seuil_points, valeur_recompense').eq('restaurant_id', req.params.id).maybeSingle();
  const nb = (notes || []).length;
  const moyenne = nb ? Math.round(((notes || []).reduce((s, n) => s + n.note, 0) / nb) * 10) / 10 : null;
  res.json({ note_moyenne: moyenne, nb_avis: nb, fidelite: fid && fid.actif ? fid : { actif: false } });
});

app.get('/api/restaurants/:id/avis', validerUuid('id'), async (req, res) => {
  const { data, error } = await supabase.from('avis').select('note, commentaire, reponse, created_at').eq('restaurant_id', req.params.id).order('created_at', { ascending: false }).limit(30);
  if (error) return echec(res, 'avis public', error);
  res.json(data);
});

app.get('/api/avis/:restaurant_id', validerUuid('restaurant_id'), exiger(['restaurant', 'admin']), async (req, res) => {
  if (!autorise(req, req.params.restaurant_id)) return res.status(403).json({ error: 'Accès refusé.' });
  const { data, error } = await supabase.from('avis').select('id, note, commentaire, reponse, reponse_at, created_at').eq('restaurant_id', req.params.restaurant_id).order('created_at', { ascending: false }).limit(100);
  if (error) return echec(res, 'liste avis', error);
  res.json(data);
});

app.put('/api/avis/:restaurant_id/:id/reponse', validerUuid('restaurant_id', 'id'), exiger(['restaurant', 'admin']), async (req, res) => {
  if (!autorise(req, req.params.restaurant_id)) return res.status(403).json({ error: 'Accès refusé.' });
  const reponse = texte(req.body && req.body.reponse, 500);
  if (!reponse) return res.status(400).json({ error: 'Écrivez votre réponse.' });
  const { data, error } = await supabase.from('avis').update({ reponse, reponse_at: new Date().toISOString() })
    .eq('id', req.params.id).eq('restaurant_id', req.params.restaurant_id).select('id, note, commentaire, reponse, reponse_at, created_at').maybeSingle();
  if (error) return echec(res, 'réponse avis', error);
  if (!data) return res.status(404).json({ error: 'Avis introuvable.' });
  res.json(data);
});

app.get('/api/fidelite/:restaurant_id', validerUuid('restaurant_id'), exiger(['restaurant', 'admin']), async (req, res) => {
  if (!autorise(req, req.params.restaurant_id)) return res.status(403).json({ error: 'Accès refusé.' });
  const { data: cfg, error } = await supabase.from('fidelite_config').select('actif, fcfa_par_point, seuil_points, valeur_recompense').eq('restaurant_id', req.params.restaurant_id).maybeSingle();
  if (error) return echec(res, 'fidélité', error);
  const { count } = await supabase.from('fidelite').select('telephone', { count: 'exact', head: true }).eq('restaurant_id', req.params.restaurant_id);
  res.json({ ...(cfg || { actif: false, fcfa_par_point: 1000, seuil_points: 10, valeur_recompense: 2000 }), nb_clients: count || 0 });
});

app.put('/api/fidelite/:restaurant_id', validerUuid('restaurant_id'), exiger(['restaurant', 'admin']), async (req, res) => {
  if (!autorise(req, req.params.restaurant_id)) return res.status(403).json({ error: 'Accès refusé.' });
  const b = req.body || {};
  const fcfa = entier(b.fcfa_par_point, 100, 1000000);
  const seuil = entier(b.seuil_points, 1, 10000);
  const valeur = entier(b.valeur_recompense, 100, 10000000);
  if (typeof b.actif !== 'boolean' || fcfa === null || seuil === null || valeur === null) return res.status(400).json({ error: 'Valeurs invalides.' });
  const { data, error } = await supabase.from('fidelite_config')
    .upsert([{ restaurant_id: req.params.restaurant_id, actif: b.actif, fcfa_par_point: fcfa, seuil_points: seuil, valeur_recompense: valeur }], { onConflict: 'restaurant_id' })
    .select('actif, fcfa_par_point, seuil_points, valeur_recompense').single();
  if (error) return echec(res, 'maj fidélité', error);
  res.json(data);
});
app.get('/api/stats/:restaurant_id', validerUuid('restaurant_id'), exiger(['restaurant', 'admin']), async (req, res) => {
  if (!autorise(req, req.params.restaurant_id)) return res.status(403).json({ error: 'Accès refusé.' });
  const depuis = new Date();
  depuis.setDate(depuis.getDate() - 30);
  const { data, error } = await supabase
    .from('commandes')
    .select('*')
    .eq('restaurant_id', req.params.restaurant_id)
    .gte('created_at', depuis.toISOString())
    .order('created_at', { ascending: false })
    .limit(5000);
  if (error) return echec(res, 'stats', error);
  res.json(data);
});

/* ───────────────────────── Erreurs ───────────────────────── */
app.use((req, res) => res.status(404).json({ error: 'Route introuvable.' }));
app.use((err, req, res, next) => {
  if (err && err.type === 'entity.too.large') return res.status(413).json({ error: 'Fichier ou requête trop volumineux.' });
  if (err && err.type === 'entity.parse.failed') return res.status(400).json({ error: 'Requête invalide.' });
  console.error('[ERREUR]', req.method, req.path, err && err.message);
  res.status(500).json({ error: 'Erreur interne du serveur.' });
});
process.on('unhandledRejection', (e) => console.error('[REJET NON GÉRÉ]', e && e.message));

const PORT = process.env.PORT || 3000;
app.listen(PORT, '0.0.0.0', () => {
  console.log(`🚀 Launge Backend démarré sur le port ${PORT}`);
  console.log(AUTH_STRICT ? '🔒 Mode strict : connexion exigée sur les routes protégées.' : '🟡 Mode transition : appels sans jeton tolérés (voir [TRANSITION] dans les logs).');
  console.log(ORIGINES.length ? `🌐 Origines autorisées : ${ORIGINES.join(', ')}` : '⚠️  CORS_ORIGINS non défini : toutes les origines sont acceptées, cookies désactivés.');
});
