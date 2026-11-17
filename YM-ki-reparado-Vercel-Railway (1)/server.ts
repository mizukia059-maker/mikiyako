import 'dotenv/config';
import express from 'express';
import fs from 'fs';
import path from 'path';
import crypto from 'crypto';
import { fileURLToPath } from 'url';
import {
  getSupabaseStatus,
  isJwtToken,
  requireSupabaseAuth,
  verifyExpressSupabaseAuth
} from './server-lib/supabaseServer';
import {
  checkSupabaseReachable,
  flushSupabaseSyncNow,
  getSupabasePersistenceConfig,
  getSupabasePersistenceMetrics,
  hydrateDatabaseFromSupabase,
  scheduleSupabaseSync,
  uploadBufferToSupabaseStorage
} from './server-lib/supabasePersistence';
import {
  ActiveSession,
  buildRateLimitKey,
  checkRateLimitStatus,
  clearExpiredSuspension,
  clearRateLimitAttempt,
  createRecoveryTokenRecord,
  evaluateSuspension,
  hashPassword,
  isReservedUsername,
  isValidUsername,
  recordFailedRateLimitAttempt,
  revokeUserSessions,
  shouldAssignFirstServerAdmin,
  verifyPassword,
  verifyRecoveryToken
} from './server-lib/authSecurity';
import {
  atomicWriteJsonFile,
  preserveAndSanitizeProfiles,
  readJsonWithBackupFallback,
  WriteQueue
} from './server-lib/dbPersistence';
import {
  appendAuditLog,
  filterChatGroupsForUser,
  filterDirectChatsForUser,
  hasDelegatedPermission,
  hasRole,
  isAdminOrFounder,
  isStatusVisibleToUser,
  resolveUsernameKey,
  sanitizeSelfProfilePatch
} from './server-lib/rbac';
import {
  evaluateAchievementEligibility,
  isUnlimitedBalanceProfile,
  validatePositiveInt,
  validatePurchaseRequest
} from './server-lib/economy';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const SERVER_START_TIME = Date.now();

const app = express();
app.set('trust proxy', 1);
const portArgIndex = process.argv.indexOf('--port');
const portArg = portArgIndex !== -1 ? parseInt(process.argv[portArgIndex + 1], 10) : null;
const PORT = portArg || (process.env.PORT ? parseInt(process.env.PORT, 10) : 3000);

const DB_FILE = path.join(__dirname, 'data', 'db.json');
const BACKUP_FILE = path.join(__dirname, 'data', 'backups', 'backup_latest.json');
const uploadsDir = path.join(__dirname, 'public', 'uploads');
const dbWriteQueue = new WriteQueue();

function sendApiError(res: express.Response, status: number, message: string, code?: string) {
  return res.status(status).json({
    success: false,
    error: message,
    ...(code ? { code } : {}),
    status
  });
}

// CORS & Preflight Support for /api/* (Browser, direct tab, and iFrame preview)
app.use('/api', (req, res, next) => {
  const origin = req.headers.origin;
  const allowedOrigins = (process.env.CORS_ALLOWED_ORIGINS || '')
    .split(',')
    .map((value) => value.trim())
    .filter(Boolean);
  const originAllowed = Boolean(origin) && (
    allowedOrigins.length === 0 || allowedOrigins.includes(origin as string)
  );

  if (originAllowed && origin) {
    res.setHeader('Access-Control-Allow-Origin', origin);
    res.setHeader('Vary', 'Origin');
  }
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, PATCH, DELETE, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-Session-Token, apikey');
  if (req.method === 'OPTIONS') {
    return res.status(origin && !originAllowed ? 403 : 204).end();
  }
  next();
});

// Centralized JSON error normalizer: guarantees every 4xx/5xx on /api/* returns valid JSON with "error"
app.use('/api', (_req, res, next) => {
  let hasJsonBody = false;
  const originalJson = res.json.bind(res);
  const originalSend = res.send.bind(res);
  const originalEnd = res.end.bind(res);

  res.json = ((body: any) => {
    hasJsonBody = true;
    return originalJson(body);
  }) as any;

  res.send = ((body?: any) => {
    if (!hasJsonBody && res.statusCode >= 400) {
      const msg =
        typeof body === 'string' && body.trim().length > 0 && !body.trim().startsWith('{') && !body.trim().startsWith('[')
          ? body.trim()
          : undefined;
      if (msg !== undefined || body === undefined || body === '') {
        hasJsonBody = true;
        return originalJson({
          success: false,
          error: msg || (res.statusCode === 403 ? 'Acceso denegado (403).' : `Error HTTP ${res.statusCode}.`),
          status: res.statusCode
        });
      }
    }
    return originalSend(body);
  }) as any;

  res.end = ((chunk?: any, encoding?: any, cb?: any) => {
    if (!hasJsonBody && res.statusCode >= 400 && !res.headersSent) {
      const fallbackMessage =
        res.statusCode === 403
          ? 'Acceso denegado (403).'
          : res.statusCode === 401
            ? 'Acceso no autorizado (401).'
            : res.statusCode === 404
              ? 'Endpoint no encontrado (404).'
              : `Error HTTP ${res.statusCode}.`;
      res.setHeader('Content-Type', 'application/json; charset=utf-8');
      return originalEnd(
        JSON.stringify({ success: false, error: fallbackMessage, status: res.statusCode }),
        'utf-8',
        typeof encoding === 'function' ? encoding : cb
      );
    }
    return originalEnd(chunk, encoding, cb);
  }) as any;

  next();
});

app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ extended: true, limit: '50mb' }));

// Security Headers & Protection Middleware (Configured for iFrame embed in AI Studio Build)
app.use((_req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-XSS-Protection', '1; mode=block');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  next();
});

// Ensure data folder and public/uploads folder exist
const dataDir = path.join(__dirname, 'data');
if (!fs.existsSync(dataDir)) {
  fs.mkdirSync(dataDir, { recursive: true });
}
if (!fs.existsSync(uploadsDir)) {
  fs.mkdirSync(uploadsDir, { recursive: true });
}

// Serve uploaded files statically
app.use('/uploads', express.static(uploadsDir));

function extractBearerToken(req: express.Request): string | null {
  const authHeader = req.headers.authorization || req.headers['x-session-token'];
  if (typeof authHeader !== 'string') return null;
  return authHeader.startsWith('Bearer ') ? authHeader.slice(7).trim() : authHeader.trim();
}

async function authenticateSession(req: express.Request, _res: express.Response, next: express.NextFunction) {
  const token = extractBearerToken(req);
  const sessions = db?.activeSessions || {};
  if (token && sessions[token]) {
    const sess = sessions[token];
    const canonicalUser = resolveUsernameKey(db?.allProfiles, sess.username);
    const profile = canonicalUser ? db.allProfiles[canonicalUser] : null;
    if (sess.expiresAt > Date.now() && profile && canonicalUser) {
      const susp = evaluateSuspension(profile);
      if (susp.expired) {
        clearExpiredSuspension(profile, db.penaltiesHistory, canonicalUser);
        saveDatabase(db);
      } else if (susp.suspended) {
        delete sessions[token];
        saveDatabase(db);
        (req as any).user = null;
        (req as any).suspensionError = susp.reason || 'Tu cuenta está suspendida.';
        return next();
      }
      (req as any).user = {
        username: canonicalUser,
        accountType: profile.accountType || 'fan',
        isFounder: !!profile.isFounder,
        token
      };
      return next();
    } else {
      delete sessions[token];
      saveDatabase(db);
    }
  }

  // Optional Supabase JWT fallback when token is a JWT and JWKS is configured
  if (isJwtToken(token) && getSupabaseStatus().hasJwks) {
    try {
      const { data: supaAuth } = await verifyExpressSupabaseAuth(req, { auth: 'user' });
      if (supaAuth?.userClaims) {
        (req as any).supabaseAuth = supaAuth;
        const claimEmail = supaAuth.userClaims.email?.toLowerCase();
        if (claimEmail && db?.allProfiles) {
          const matchedUsername = Object.keys(db.allProfiles).find(
            (uname) => db.allProfiles[uname]?.email?.toLowerCase() === claimEmail
          );
          if (matchedUsername) {
            const profile = db.allProfiles[matchedUsername];
            const susp = evaluateSuspension(profile);
            if (susp.suspended) {
              (req as any).user = null;
              (req as any).suspensionError = susp.reason || 'Tu cuenta está suspendida.';
              return next();
            }
            (req as any).user = {
              username: matchedUsername,
              accountType: profile.accountType || 'fan',
              isFounder: !!profile.isFounder,
              token,
              supabaseUserId: supaAuth.userClaims.id
            };
            return next();
          }
        }
      }
    } catch {
      // Fall through cleanly as unauthenticated local user
    }
  }

  (req as any).user = null;
  next();
}

app.use(authenticateSession);

function requireAuth(req: any, res: any, next: any) {
  if (req.suspensionError) {
    return res.status(403).json({ error: req.suspensionError });
  }
  if (!req.user || !req.user.username) {
    return res.status(401).json({ error: 'Acceso no autorizado. Inicia sesión para continuar.' });
  }
  next();
}

function requireRole(allowedRoles: string[]) {
  return (req: any, res: any, next: any) => {
    if (req.suspensionError) {
      return res.status(403).json({ error: req.suspensionError });
    }
    if (!req.user || !req.user.username) {
      return res.status(401).json({ error: 'Acceso no autorizado. Inicia sesión para continuar.' });
    }
    if (hasRole(req.user, allowedRoles)) {
      return next();
    }
    return res.status(403).json({ error: 'Permisos insuficientes para realizar esta operación administrativa.' });
  };
}

function requireDelegation(permissionKey: 'canApproveArtist' | 'canApproveTrainee' | 'canManageAuditions' | 'canManageStore' | 'canManageSurvival') {
  return (req: any, res: any, next: any) => {
    if (!req.user || !req.user.username) {
      return res.status(401).json({ error: 'Acceso no autorizado.' });
    }
    if (hasDelegatedPermission(req.user, db.adminDelegations, permissionKey, db.firstRegisteredUser)) {
      return next();
    }
    return res.status(403).json({
      error: `Permiso delegado "${permissionKey}" no habilitado para tu cuenta administrativa.`
    });
  };
}

interface SharedDbState {
  registeredUsersCount: number;
  firstRegisteredUser: string;
  allProfiles: Record<string, any>;
  userCredentials: Record<string, { salt: string; hash: string; isFounder?: boolean; lastLogin?: string }>;
  activeSessions?: Record<string, ActiveSession>;
  missions: any[];
  missionClaims: any[];
  missionProgress: Record<string, Record<string, number>>;
  economyLedger: any[];
  wishlists: Record<string, any[]>;
  showcaseCollections: Record<string, any[]>;
  loginAttempts: Record<string, { count: number; lockedUntil?: number }>;
  userReports: any[];
  blockedUsers: Record<string, string[]>;
  survivals: any[];
  forums: any[];
  posts: any[];
  fanClubs: any[];
  chats: Record<string, any[]>;
  chatGroups: any[];
  products: any[];
  inventory: any[];
  userAlbums: any[];
  userPhotocards: any[];
  magazines: any[];
  releases: any[];
  awards: any[];
  userAwardVotes: Record<string, number>;
  userVotedNominees: Record<string, string[]>;
  auditions: any[];
  auditionPassCodes: any[];
  notifications: any[];
  tradeOffers: any[];
  ceoRequests: any[];
  partners: any[];
  charts: any[];
  reviews: Record<string, any[]>;
  adminDelegations: Record<string, any>;
  adminAuditLog: any[];
  userRequests: any[];
  achievements: any[];
  calendarEvents: any[];
  penaltiesHistory: any[];
  collaborations: any[];
  followers: Array<{ id: string; followerUsername: string; followingUsername: string; followedAt: string }>;
  userStatuses: Record<string, { username: string; text: string; emoji: string; visibility: string; expiresAt?: string | null; updatedAt: string }>;
  postReactions: Record<string, Record<string, string>>;
  commentReactions: Record<string, Record<string, string>>;
  savedCollections: Record<string, any[]>;
  savedPosts: Record<string, any[]>;
  vendors: any[];
  productVariants: Record<string, any[]>;
  inventoryMovements: any[];
  discountCoupons: any[];
  productPurchases: any[];
  passwordResetTokens?: Record<string, { codeHash: string; expiresAt: number }>;
  lastUpdated: string;
}

function getDefaultMissions(): any[] {
  return [
    {
      id: 'dm-post',
      category: 'daily',
      title: 'Publicar en Foros Oficiales',
      description: 'Comparte un tema, debate o anuncio en los foros comunitarios.',
      reqType: 'publish_posts',
      targetCount: 1,
      rewardCoins: 250,
      rewardGems: 5,
      isActive: true,
      createdAt: new Date().toISOString()
    },
    {
      id: 'dm-comment',
      category: 'daily',
      title: 'Interacción Comunitaria',
      description: 'Escribe al menos 2 comentarios en publicaciones de la comunidad.',
      reqType: 'write_comments',
      targetCount: 2,
      rewardCoins: 150,
      rewardGems: 3,
      isActive: true,
      createdAt: new Date().toISOString()
    },
    {
      id: 'dm-listen',
      category: 'daily',
      title: 'Sesión Sonora en YM-ki',
      description: 'Escucha canciones oficiales de los lanzamientos y álbumes de la plataforma.',
      reqType: 'listen_tracks',
      targetCount: 1,
      rewardCoins: 100,
      rewardGems: 2,
      isActive: true,
      createdAt: new Date().toISOString()
    },
    {
      id: 'wm-collect',
      category: 'weekly',
      title: 'Coleccionista Activo de Merch',
      description: 'Adquiere productos en la tienda o exhibe 2 artículos en tu vitrina de merchandising.',
      reqType: 'collect_items',
      targetCount: 2,
      rewardCoins: 1000,
      rewardGems: 30,
      isActive: true,
      createdAt: new Date().toISOString()
    },
    {
      id: 'wm-vote',
      category: 'weekly',
      title: 'Votante en Premiaciones o Survivals',
      description: 'Participa con tu voto oficial en al menos 3 categorías de premiaciones o rondas de talentos.',
      reqType: 'award_vote',
      targetCount: 3,
      rewardCoins: 800,
      rewardGems: 25,
      isActive: true,
      createdAt: new Date().toISOString()
    },
    {
      id: 'wm-transfer',
      category: 'weekly',
      title: 'Generosidad Estelar (Gem Transfer)',
      description: 'Apoya a un colega fan o artista transfiriendo Gemas de tu cuenta.',
      reqType: 'gem_transfer',
      targetCount: 1,
      rewardCoins: 600,
      rewardGems: 20,
      isActive: true,
      createdAt: new Date().toISOString()
    },
    {
      id: 'mm-fandom',
      category: 'monthly',
      title: 'Pasión de Fandom Oficial',
      description: 'Únete a un club de fans oficial y activa su etiqueta de fandom en tu perfil.',
      reqType: 'join_fanclub',
      targetCount: 1,
      rewardCoins: 3000,
      rewardGems: 100,
      isActive: true,
      createdAt: new Date().toISOString()
    },
    {
      id: 'mm-customize',
      category: 'monthly',
      title: 'Identidad y Estilo Escénico',
      description: 'Personaliza tu foto de perfil, marco exterior o color de aura en la plataforma.',
      reqType: 'customize_profile',
      targetCount: 1,
      rewardCoins: 2000,
      rewardGems: 70,
      isActive: true,
      createdAt: new Date().toISOString()
    },
    {
      id: 'mm-posts-grand',
      category: 'monthly',
      title: 'Creador Estrella del Mes',
      description: 'Alcanza 10 publicaciones o comentarios en la red social de YM-ki Records.',
      reqType: 'publish_posts',
      targetCount: 10,
      rewardCoins: 4500,
      rewardGems: 150,
      isActive: true,
      createdAt: new Date().toISOString()
    }
  ];
}

function getDefaultAchievements(): any[] {
  return [
    {
      id: 'ach-first-purchase',
      category: 'compras',
      title: 'First Purchase',
      description: 'Realiza tu primera compra oficial en la Tienda u Outlet de YM-ki Records.',
      icon: '🛍️',
      reqType: 'first_purchase',
      targetCount: 1,
      rewardCoins: 300,
      rewardGems: 10,
      rewardBadge: {
        id: 'badge-first-shopper',
        name: 'Shopper Novato',
        image: 'https://images.unsplash.com/photo-1555529669-e69e7aa0ba9a?w=120&auto=format&fit=crop&q=80',
        rarity: 'comun'
      },
      isSecret: false,
      createdAt: new Date().toISOString()
    },
    {
      id: 'ach-collector',
      category: 'coleccion',
      title: 'Collector Master',
      description: 'Colecciona al menos 10 photocards exclusivas en tu inventario.',
      icon: '🎴',
      reqType: 'photocards_count',
      targetCount: 10,
      rewardCoins: 800,
      rewardGems: 25,
      rewardBadge: {
        id: 'badge-photocard-collector',
        name: 'Collector Master',
        image: 'https://images.unsplash.com/photo-1618005182384-a83a8bd57fbe?w=120&auto=format&fit=crop&q=80',
        rarity: 'epica'
      },
      isSecret: false,
      createdAt: new Date().toISOString()
    },
    {
      id: 'ach-super-fan',
      category: 'actividad',
      title: 'Super Fan',
      description: 'Participa con tu voto oficial en 10 categorías o votaciones de la plataforma.',
      icon: '🌟',
      reqType: 'votes_count',
      targetCount: 10,
      rewardCoins: 600,
      rewardGems: 20,
      rewardBadge: {
        id: 'badge-super-fan',
        name: 'Super Fan Star',
        image: 'https://images.unsplash.com/photo-1514525253161-7a46d19cd819?w=120&auto=format&fit=crop&q=80',
        rarity: 'rara'
      },
      isSecret: false,
      createdAt: new Date().toISOString()
    },
    {
      id: 'ach-rising-star',
      category: 'audiciones',
      title: 'Rising Star',
      description: 'Envía y completa satisfactoriamente una audición a los CEOs evaluadores.',
      icon: '🎤',
      reqType: 'audition_completed',
      targetCount: 1,
      rewardCoins: 500,
      rewardGems: 15,
      rewardBadge: {
        id: 'badge-rising-star',
        name: 'Rising Star Talent',
        image: 'https://images.unsplash.com/photo-1516280440614-37939bbacd81?w=120&auto=format&fit=crop&q=80',
        rarity: 'rara'
      },
      isSecret: false,
      createdAt: new Date().toISOString()
    },
    {
      id: 'ach-debut-ready',
      category: 'survival',
      title: 'Debut Ready',
      description: 'Completa o participa activamente en un show o competencia de Survival.',
      icon: '🔥',
      reqType: 'survival_completed',
      targetCount: 1,
      rewardCoins: 1200,
      rewardGems: 50,
      rewardBadge: {
        id: 'badge-survival-pro',
        name: 'Debut Ready Survivor',
        image: 'https://images.unsplash.com/photo-1492684223066-81342ee5ff30?w=120&auto=format&fit=crop&q=80',
        rarity: 'legendaria'
      },
      isSecret: false,
      createdAt: new Date().toISOString()
    },
    {
      id: 'ach-music-lover',
      category: 'musical',
      title: 'Music Lover',
      description: 'Reproduce y disfruta 20 tracks de álbumes o lanzamientos oficiales.',
      icon: '🎧',
      reqType: 'tracks_listened',
      targetCount: 20,
      rewardCoins: 400,
      rewardGems: 15,
      rewardBadge: {
        id: 'badge-audiophile',
        name: 'Melómano Élite',
        image: 'https://images.unsplash.com/photo-1511671782779-c97d3d27a1d4?w=120&auto=format&fit=crop&q=80',
        rarity: 'comun'
      },
      isSecret: false,
      createdAt: new Date().toISOString()
    },
    {
      id: 'ach-community-star',
      category: 'comunidad',
      title: 'Community Star',
      description: 'Publica temas o comentarios al menos 5 veces en los foros comunitarios.',
      icon: '💬',
      reqType: 'community_posts',
      targetCount: 5,
      rewardCoins: 500,
      rewardGems: 15,
      rewardBadge: {
        id: 'badge-community-pillar',
        name: 'Pilar Comunitario',
        image: 'https://images.unsplash.com/photo-1522071820081-009f0129c71c?w=120&auto=format&fit=crop&q=80',
        rarity: 'rara'
      },
      isSecret: false,
      createdAt: new Date().toISOString()
    },
    {
      id: 'ach-secret-generosity',
      category: 'especiales',
      title: 'Generosidad Galáctica',
      description: 'Transfiere Gemas a otro usuario para apoyarle.',
      icon: '💎',
      reqType: 'gem_transfer',
      targetCount: 1,
      rewardCoins: 900,
      rewardGems: 30,
      rewardBadge: {
        id: 'badge-secret-angel',
        name: 'Corazón de Oro',
        image: 'https://images.unsplash.com/photo-1518709268805-4e9042af9f23?w=120&auto=format&fit=crop&q=80',
        rarity: 'mitica'
      },
      isSecret: true,
      createdAt: new Date().toISOString()
    },
    {
      id: 'ach-secret-custom',
      category: 'especiales',
      title: 'Aura Deslumbrante',
      description: 'Personaliza tu perfil con marcos transparentes y auras de color.',
      icon: '✨',
      reqType: 'profile_customized',
      targetCount: 1,
      rewardCoins: 600,
      rewardGems: 25,
      rewardBadge: {
        id: 'badge-secret-fashionista',
        name: 'Icono Visual',
        image: 'https://images.unsplash.com/photo-1550684848-fac1c5b4e853?w=120&auto=format&fit=crop&q=80',
        rarity: 'epica'
      },
      isSecret: true,
      createdAt: new Date().toISOString()
    },
    {
      id: 'ach-collab-pioneer',
      category: 'empresas',
      title: 'Alianza Estratégica',
      description: 'Completa o participa con éxito en un proyecto de colaboración oficial.',
      icon: '🤝',
      reqType: 'collaboration_completed',
      targetCount: 1,
      rewardCoins: 1500,
      rewardGems: 60,
      rewardBadge: {
        id: 'badge-collab-pioneer',
        name: 'Líder Colaborativo',
        image: 'https://images.unsplash.com/photo-1556761175-5973dc0f32e7?w=120&auto=format&fit=crop&q=80',
        rarity: 'mitica'
      },
      isSecret: false,
      createdAt: new Date().toISOString()
    }
  ];
}

function getDefaultCalendarEvents(): any[] {
  return [
    {
      id: 'cal-event-1',
      name: 'Gran Gala YM-ki Awards 2026',
      image: 'https://images.unsplash.com/photo-1470225620780-dba8ba36b745?w=600&auto=format&fit=crop&q=80',
      description: 'Ceremonia de premiación en vivo y anuncio de ganadores elegidos por el fandom.',
      category: 'premiacion',
      startDate: '2026-11-20',
      endDate: '2026-11-20',
      time: '20:00',
      company: 'YM-ki Records',
      relatedSection: 'premiaciones',
      isPrivate: false,
      createdBy: 'admin',
      isAutomated: true,
      sourceModule: 'awards',
      createdAt: new Date().toISOString()
    },
    {
      id: 'cal-event-2',
      name: 'Audiciones Abiertas Invierno 2026',
      image: 'https://images.unsplash.com/photo-1516280440614-37939bbacd81?w=600&auto=format&fit=crop&q=80',
      description: 'Convocatoria global para nuevos talentos vocales, rap, baile y compositores.',
      category: 'convocatoria',
      startDate: '2026-11-10',
      endDate: '2026-11-30',
      time: '12:00',
      company: 'YM-ki Entertainment',
      relatedSection: 'audiciones',
      isPrivate: false,
      createdBy: 'admin',
      isAutomated: true,
      sourceModule: 'auditions',
      createdAt: new Date().toISOString()
    },
    {
      id: 'cal-event-3',
      name: 'Showcase Survival: Ronda 1',
      image: 'https://images.unsplash.com/photo-1492684223066-81342ee5ff30?w=600&auto=format&fit=crop&q=80',
      description: 'Presentación de equipos y evaluación en vivo por jueces y mentores.',
      category: 'survival',
      startDate: '2026-11-15',
      endDate: '2026-11-17',
      time: '18:00',
      company: 'YM-ki Studios',
      relatedSection: 'survival',
      isPrivate: false,
      createdBy: 'admin',
      isAutomated: true,
      sourceModule: 'survival',
      createdAt: new Date().toISOString()
    }
  ];
}

function sanitizeDb(data: SharedDbState): SharedDbState {
  if (!data.allProfiles || typeof data.allProfiles !== 'object') data.allProfiles = {};
  if (!data.userCredentials || typeof data.userCredentials !== 'object') data.userCredentials = {};
  if (!data.activeSessions || typeof data.activeSessions !== 'object') data.activeSessions = {};
  if (!Array.isArray(data.missions) || data.missions.length === 0) data.missions = getDefaultMissions();
  if (!Array.isArray(data.missionClaims)) data.missionClaims = [];
  if (!data.missionProgress || typeof data.missionProgress !== 'object') data.missionProgress = {};
  if (!Array.isArray(data.economyLedger)) data.economyLedger = [];
  if (!data.wishlists || typeof data.wishlists !== 'object') data.wishlists = {};
  if (!data.showcaseCollections || typeof data.showcaseCollections !== 'object') data.showcaseCollections = {};
  if (!data.loginAttempts || typeof data.loginAttempts !== 'object') data.loginAttempts = {};
  if (!Array.isArray(data.userReports)) data.userReports = [];
  if (!data.blockedUsers || typeof data.blockedUsers !== 'object') data.blockedUsers = {};

  // STRICT PRESERVATION RULE: Never delete existing profiles even if credentials are missing; mark them pending_recovery.
  const preservation = preserveAndSanitizeProfiles(data.allProfiles, data.userCredentials);
  data.registeredUsersCount = preservation.totalProfiles;

  // Clean expired sessions silently
  const now = Date.now();
  for (const [tok, sess] of Object.entries(data.activeSessions)) {
    if (!sess || typeof sess !== 'object' || sess.expiresAt <= now) {
      delete data.activeSessions[tok];
    }
  }

  // Filter out corrupted ledger / purchase / notification entries
  data.economyLedger = data.economyLedger.filter((tx: any) => tx && typeof tx.username === 'string' && tx.username.trim().length > 0);
  if (Array.isArray(data.productPurchases)) {
    data.productPurchases = data.productPurchases.filter((p: any) => p && typeof p.buyerUsername === 'string' && p.buyerUsername.trim().length > 0);
  }
  if (Array.isArray(data.notifications)) {
    data.notifications = data.notifications.filter((n: any) => n && typeof n.recipient === 'string' && n.recipient.trim().length > 0);
  }
  if (!data.passwordResetTokens || typeof data.passwordResetTokens !== 'object') {
    data.passwordResetTokens = {};
  }

  if (!data.firstRegisteredUser || !data.allProfiles[data.firstRegisteredUser]) {
    const founderUser = Object.keys(data.allProfiles).find((u) => data.allProfiles[u]?.isFounder);
    data.firstRegisteredUser = founderUser || '';
  }

  // Ensure default arrays
  if (!Array.isArray(data.survivals)) data.survivals = [];
  if (!Array.isArray(data.forums)) data.forums = [];
  if (!Array.isArray(data.posts)) data.posts = [];
  if (!Array.isArray(data.fanClubs)) data.fanClubs = [];
  if (!data.chats || typeof data.chats !== 'object') data.chats = {};
  if (!Array.isArray(data.chatGroups)) data.chatGroups = [];
  if (!Array.isArray(data.products)) data.products = [];
  if (!Array.isArray(data.inventory)) data.inventory = [];
  if (!Array.isArray(data.userAlbums)) data.userAlbums = [];
  if (!Array.isArray(data.userPhotocards)) data.userPhotocards = [];
  if (!Array.isArray(data.magazines)) data.magazines = [];
  if (!Array.isArray(data.releases)) data.releases = [];
  if (!Array.isArray(data.awards)) data.awards = [];
  if (!data.userAwardVotes || typeof data.userAwardVotes !== 'object') data.userAwardVotes = {};
  if (!data.userVotedNominees || typeof data.userVotedNominees !== 'object') data.userVotedNominees = {};
  if (!Array.isArray(data.auditions)) data.auditions = [];
  if (!Array.isArray(data.auditionPassCodes)) data.auditionPassCodes = [];
  if (!Array.isArray(data.notifications)) data.notifications = [];
  if (!Array.isArray(data.tradeOffers)) data.tradeOffers = [];
  if (!Array.isArray(data.ceoRequests)) data.ceoRequests = [];
  if (!Array.isArray(data.partners)) data.partners = [];
  if (!Array.isArray(data.charts)) data.charts = [];
  if (!data.reviews || typeof data.reviews !== 'object') data.reviews = {};
  if (!data.adminDelegations || typeof data.adminDelegations !== 'object') data.adminDelegations = {};
  if (!Array.isArray(data.adminAuditLog)) data.adminAuditLog = [];
  if (!Array.isArray(data.userRequests)) data.userRequests = [];
  if (!Array.isArray(data.achievements) || data.achievements.length === 0) data.achievements = getDefaultAchievements();
  if (!Array.isArray(data.calendarEvents) || data.calendarEvents.length === 0) data.calendarEvents = getDefaultCalendarEvents();
  if (!Array.isArray(data.penaltiesHistory)) data.penaltiesHistory = [];
  if (!Array.isArray(data.collaborations)) data.collaborations = [];
  if (!Array.isArray(data.followers)) data.followers = [];
  if (!data.userStatuses || typeof data.userStatuses !== 'object') data.userStatuses = {};
  if (!data.postReactions || typeof data.postReactions !== 'object') data.postReactions = {};
  if (!data.commentReactions || typeof data.commentReactions !== 'object') data.commentReactions = {};
  if (!data.savedCollections || typeof data.savedCollections !== 'object') data.savedCollections = {};
  if (!data.savedPosts || typeof data.savedPosts !== 'object') data.savedPosts = {};
  if (!Array.isArray(data.vendors)) data.vendors = [];
  if (!data.productVariants || typeof data.productVariants !== 'object') {
    data.productVariants = {
      'prod-bundle-miki-superpack': [
        { id: 'var-b1', productId: 'prod-bundle-miki-superpack', name: 'Edición Estándar Gold', variantType: 'edition', priceCoins: 3500, priceGems: 30, stockCount: 15, sku: 'BUN-GLD-01' },
        { id: 'var-b2', productId: 'prod-bundle-miki-superpack', name: 'Edición Coleccionista Diamond', variantType: 'edition', priceCoins: 4200, priceGems: 45, stockCount: 10, sku: 'BUN-DIA-02' }
      ],
      'prod-general-ren-varsity': [
        { id: 'var-v1', productId: 'prod-general-ren-varsity', name: 'Talla M - Negro Obsidiana', variantType: 'size', priceCoins: 2200, priceGems: 20, stockCount: 12, sku: 'VAR-BLK-M' },
        { id: 'var-v2', productId: 'prod-general-ren-varsity', name: 'Talla L - Negro Obsidiana', variantType: 'size', priceCoins: 2200, priceGems: 20, stockCount: 10, sku: 'VAR-BLK-L' },
        { id: 'var-v3', productId: 'prod-general-ren-varsity', name: 'Talla XL - Edición Holográfica Neón', variantType: 'edition', priceCoins: 2600, priceGems: 25, stockCount: 8, sku: 'VAR-NEO-XL' }
      ]
    };
  }
  if (!Array.isArray(data.inventoryMovements)) data.inventoryMovements = [];
  if (!Array.isArray(data.discountCoupons) || data.discountCoupons.length === 0) {
    data.discountCoupons = [
      { id: 'coup-1', code: 'WELCOME10', discountPercent: 10, minPurchaseCoins: 500, maxUses: 500, usesCount: 12, isActive: true, createdAt: '2026-11-01T00:00:00.000Z' },
      { id: 'coup-2', code: 'STARLIGHT20', discountPercent: 20, minPurchaseCoins: 1000, maxUses: 200, usesCount: 5, isActive: true, createdAt: '2026-11-01T00:00:00.000Z' },
      { id: 'coup-3', code: 'VIPYMKI30', discountPercent: 30, minPurchaseCoins: 2000, maxUses: 50, usesCount: 2, isActive: true, createdAt: '2026-11-01T00:00:00.000Z' }
    ];
  }
  if (!Array.isArray(data.productPurchases)) data.productPurchases = [];

  if (!data.lastUpdated && (!Array.isArray(data.products) || data.products.length === 0)) {
    const sampleFrames = [
      {
        id: 'frame-cyber-neon',
        name: 'Marco Cibernético Neón',
        description: 'Marco luminoso con resplandor cian e iluminación de vanguardia para tu foto de perfil.',
        images: ['https://images.unsplash.com/photo-1550751827-4bd374c3f58b?w=400&h=400&fit=crop'],
        tags: ['Marco', 'Neón', 'Cyberpunk'],
        stockType: 'unlimited',
        stockCount: 9999,
        associatedArtists: ['YM-ki All Stars'],
        currencyType: 'coins',
        priceCoins: 800,
        priceGems: 15,
        createdBy: 'admin',
        isOutlet: false,
        createdAt: new Date().toISOString(),
        category: 'merch',
        isFrame: true,
        frameConfig: { style: 'cyber_neon', defaultColor: '#06b6d4', rarity: 'rara' },
        isFeatured: true
      },
      {
        id: 'frame-gold-star',
        name: 'Marco Dorado Starlight VIP',
        description: 'Elegante halo dorado de alta costura para fotos de perfil oficiales y miembros distinguidos.',
        images: ['https://images.unsplash.com/photo-1518709268805-4e9042af9f23?w=400&h=400&fit=crop'],
        tags: ['Marco', 'Oro', 'Starlight', 'VIP'],
        stockType: 'fixed',
        stockCount: 50,
        associatedArtists: ['YM-ki All Stars'],
        currencyType: 'both',
        priceCoins: 1500,
        priceGems: 35,
        createdBy: 'admin',
        isOutlet: false,
        createdAt: new Date().toISOString(),
        category: 'merch',
        isFrame: true,
        frameConfig: { style: 'gold_star', defaultColor: '#eab308', rarity: 'limitada' },
        isFeatured: true,
        isRecent: true
      },
      {
        id: 'frame-prism-diamond',
        name: 'Marco Prisma de Diamante',
        description: 'Borde reflectivo de cristal con resplandor amatista y corte de joya premium.',
        images: ['https://images.unsplash.com/photo-1534447677768-be436bb09401?w=400&h=400&fit=crop'],
        tags: ['Marco', 'Gemas', 'Diamante'],
        stockType: 'unlimited',
        stockCount: 999,
        associatedArtists: ['YM-ki Trainees'],
        currencyType: 'gems',
        priceCoins: 0,
        priceGems: 60,
        createdBy: 'admin',
        isOutlet: false,
        createdAt: new Date().toISOString(),
        category: 'merch',
        isFrame: true,
        frameConfig: { style: 'prism_diamond', defaultColor: '#a855f7', rarity: 'exclusiva' }
      },
      {
        id: 'frame-sakura-blossom',
        name: 'Marco Floración Sakura',
        description: 'Delicado marco primaveral con pétalos y halo rosa pastel para tu avatar.',
        images: ['https://images.unsplash.com/photo-1522383225653-ed111181a951?w=400&h=400&fit=crop'],
        tags: ['Marco', 'Sakura', 'Primavera'],
        stockType: 'unlimited',
        stockCount: 999,
        associatedArtists: ['YM-ki Trainees'],
        currencyType: 'coins',
        priceCoins: 650,
        priceGems: 10,
        createdBy: 'admin',
        isOutlet: false,
        createdAt: new Date().toISOString(),
        category: 'merch',
        isFrame: true,
        frameConfig: { style: 'sakura', defaultColor: '#f43f5e', rarity: 'permanente' }
      }
    ];
    data.products.push(...sampleFrames);
  }

  return data;
}

let lastPersistenceWarning: string | null = null;

function loadDatabase(): SharedDbState {
  const loaded = readJsonWithBackupFallback<SharedDbState>(DB_FILE, BACKUP_FILE);
  if (loaded.data) {
    if (loaded.source === 'backup') {
      lastPersistenceWarning = `Se restauró la base de datos desde backup_latest.json (${loaded.error || 'archivo principal ilegible'}).`;
      console.warn(lastPersistenceWarning);
    }
    const sanitized = sanitizeDb(loaded.data);
    if (loaded.source === 'backup') {
      saveDatabase(sanitized);
    }
    return sanitized;
  }

  if (loaded.error) {
    lastPersistenceWarning = `Error cargando db.json y respaldo: ${loaded.error}`;
    console.error(lastPersistenceWarning);
  }

  const initialDb: SharedDbState = {
    registeredUsersCount: 0,
    firstRegisteredUser: '',
    allProfiles: {},
    userCredentials: {},
    missions: getDefaultMissions(),
    missionClaims: [],
    missionProgress: {},
    economyLedger: [],
    wishlists: {},
    showcaseCollections: {},
    loginAttempts: {},
    userReports: [],
    blockedUsers: {},
    survivals: [],
    forums: [],
    posts: [],
    fanClubs: [],
    chats: {},
    chatGroups: [],
    products: [],
    inventory: [],
    userAlbums: [],
    userPhotocards: [],
    magazines: [],
    releases: [],
    awards: [],
    userAwardVotes: {},
    userVotedNominees: {},
    auditions: [],
    auditionPassCodes: [],
    notifications: [],
    tradeOffers: [],
    ceoRequests: [],
    partners: [],
    charts: [],
    reviews: {},
    adminDelegations: {},
    adminAuditLog: [],
    userRequests: [],
    achievements: getDefaultAchievements(),
    calendarEvents: getDefaultCalendarEvents(),
    penaltiesHistory: [],
    collaborations: [],
    followers: [],
    userStatuses: {},
    postReactions: {},
    commentReactions: {},
    savedCollections: {},
    savedPosts: {},
    vendors: [],
    productVariants: {},
    inventoryMovements: [],
    discountCoupons: [],
    productPurchases: [],
    lastUpdated: new Date().toISOString()
  };

  persistLocalSnapshot(initialDb);
  return initialDb;
}

function autoBackupDatabase(data: SharedDbState) {
  try {
    atomicWriteJsonFile(BACKUP_FILE, data);
  } catch (err) {
    console.error('Auto-backup warning:', err);
  }
}

function persistLocalSnapshot(data: SharedDbState) {
  sanitizeDb(data);
  data.lastUpdated = new Date().toISOString();
  const snapshot = JSON.parse(JSON.stringify(data));
  void dbWriteQueue.enqueue(() => {
    try {
      atomicWriteJsonFile(DB_FILE, snapshot);
      autoBackupDatabase(snapshot);
    } catch (err) {
      console.error('Error saving db.json:', err);
    }
  });
  return snapshot;
}

function saveDatabase(data: SharedDbState) {
  const snapshot = persistLocalSnapshot(data);
  scheduleSupabaseSync(snapshot, 500);
}

function getSafeProfiles(data: SharedDbState, requestingUser?: string) {
  const safe: Record<string, any> = {};
  if (!data.allProfiles) return safe;
  const reqKey = resolveUsernameKey(data.allProfiles, requestingUser);
  const reqProfile = reqKey ? data.allProfiles[reqKey] : null;
  const isPrivileged = Boolean(reqProfile?.isFounder || reqProfile?.accountType === 'admin');

  for (const [username, p] of Object.entries(data.allProfiles)) {
    const isSelf = requestingUser && requestingUser.toLowerCase() === username.toLowerCase();
    const canSeeBalances = isSelf || isPrivileged;

    safe[username] = {
      username: p.username,
      nickname: p.nickname || p.username,
      avatar: p.avatar,
      banner: p.banner,
      description: p.description,
      ringColor: p.ringColor,
      transparentFrame: p.transparentFrame,
      customTransparentFrame: p.customTransparentFrame,
      accountType: p.accountType,
      isFounder: !!p.isFounder,
      isCoCeo: !!p.isCoCeo,
      traineeRank: p.traineeRank,
      profileBgColor: p.profileBgColor,
      badgeAdminColor: p.badgeAdminColor,
      badgeVerifiedColor: p.badgeVerifiedColor,
      animal: p.animal,
      allowMessages: p.allowMessages !== false,
      dob: (isSelf || isPrivileged) ? p.dob : undefined,
      isMerchPrivate: p.isMerchPrivate,
      showcaseItemIds: p.showcaseItemIds || [],
      completedMissions: (isSelf || isPrivileged) ? p.completedMissions || [] : [],
      lastDailyClaim: isSelf ? p.lastDailyClaim : undefined,
      fandomDisplayMode: p.fandomDisplayMode || 'beside_username',
      displayedFandomTags: p.displayedFandomTags || [],
      ownedFrames: p.ownedFrames || [],
      selectedFrameId: p.selectedFrameId,
      customFrameColor: p.customFrameColor,
      frameScale: p.frameScale,
      frameOffsetX: p.frameOffsetX,
      frameOffsetY: p.frameOffsetY,
      idCard: p.idCard,
      email: (isSelf || isPrivileged) ? p.email : undefined,
      userStatus: data.userStatuses?.[username] || null,
      unlockedAchievements: p.unlockedAchievements || {},
      customBadges: p.customBadges || [],
      displayedBadges: p.displayedBadges || [],
      digitalTrophies: p.digitalTrophies || [],
      winnerCertificates: p.winnerCertificates || [],
      recognitionTitles: p.recognitionTitles || [],
      subscribedEventIds: isSelf ? (p.subscribedEventIds || []) : [],
      calendarPreferences: isSelf ? p.calendarPreferences : undefined,
      notificationPreferences: isSelf ? p.notificationPreferences : undefined,
      mutedConversations: isSelf ? (p.mutedConversations || []) : [],
      buttonTheme: p.buttonTheme,
      isSuspended: !!p.isSuspended,
      suspensionReason: (isSelf || isPrivileged) ? p.suspensionReason : undefined,
      suspensionExpires: (isSelf || isPrivileged) ? p.suspensionExpires : undefined,
      credentialsPendingRecovery: (isSelf || isPrivileged) ? !!p.credentialsPendingRecovery : undefined,
      accessStatus: p.accessStatus || 'active',
      isVendorApproved: !!p.isVendorApproved,
      vendorName: p.vendorName,
      isVerified: !!p.isVerified,
      userBiases: p.userBiases || [],
      coins: canSeeBalances ? p.coins : undefined,
      gems: canSeeBalances ? p.gems : undefined
    };
  }
  return safe;
}

function getPublicState(data: SharedDbState, requestingUser?: string) {
  const reqKey = resolveUsernameKey(data.allProfiles, requestingUser);
  const reqProfile = reqKey ? data.allProfiles[reqKey] : null;
  const isPrivileged = Boolean(reqProfile?.isFounder || reqProfile?.accountType === 'admin');
  const isModerator = reqProfile?.accountType === 'moderador';
  const reqLower = reqKey?.toLowerCase();

  const knownUsernames = Object.keys(data.allProfiles || {});
  const safeChats = filterDirectChatsForUser(data.chats, reqKey || undefined, isPrivileged, knownUsernames);
  const safeChatGroups = filterChatGroupsForUser(data.chatGroups, reqKey || undefined, isPrivileged);

  const safeNotifications = reqLower
    ? (data.notifications || []).filter((n) => n?.recipient && n.recipient.toLowerCase() === reqLower)
    : [];

  const safeSurvivals = (data.survivals || []).map((s: any) => {
    if (!s || typeof s !== 'object') return s;
    const isCreator = reqLower && s.createdBy?.toLowerCase() === reqLower;
    if (isPrivileged || isCreator) return s;
    return {
      ...s,
      applications: Array.isArray(s.applications)
        ? s.applications.filter((a: any) => reqLower && a?.applicantUsername?.toLowerCase() === reqLower)
        : []
    };
  });

  const safeStatuses: Record<string, any> = {};
  for (const [uname, st] of Object.entries(data.userStatuses || {})) {
    if (isStatusVisibleToUser(st, reqKey || undefined, isPrivileged, data.followers || [])) {
      safeStatuses[uname] = st;
    }
  }

  const wishlistKey = resolveUsernameKey(data.wishlists, reqKey || undefined);
  const showcaseKey = resolveUsernameKey(data.showcaseCollections, reqKey || undefined);
  const blockedKey = resolveUsernameKey(data.blockedUsers, reqKey || undefined);
  const awardVotesKey = resolveUsernameKey(data.userAwardVotes, reqKey || undefined);
  const votedNomineesKey = resolveUsernameKey(data.userVotedNominees, reqKey || undefined);
  const savedColKey = resolveUsernameKey(data.savedCollections, reqKey || undefined);
  const savedPostsKey = resolveUsernameKey(data.savedPosts, reqKey || undefined);

  return {
    registeredUsersCount: data.registeredUsersCount || 0,
    firstRegisteredUser: data.firstRegisteredUser || '',
    allProfiles: getSafeProfiles(data, reqKey || undefined),
    missions: data.missions || [],
    economyLedger: reqLower
      ? (data.economyLedger || []).filter((tx) => tx?.username && tx.username.toLowerCase() === reqLower)
      : [],
    wishlists: reqKey ? { [reqKey]: (wishlistKey && data.wishlists?.[wishlistKey]) || [] } : {},
    showcaseCollections: reqKey ? { [reqKey]: (showcaseKey && data.showcaseCollections?.[showcaseKey]) || [] } : {},
    blockedUsers: reqKey ? { [reqKey]: (blockedKey && data.blockedUsers?.[blockedKey]) || [] } : {},
    survivals: safeSurvivals,
    forums: data.forums || [],
    posts: data.posts || [],
    fanClubs: data.fanClubs || [],
    chats: safeChats,
    chatGroups: safeChatGroups,
    products: data.products || [],
    productVariants: data.productVariants || {},
    inventory: reqLower
      ? (data.inventory || []).filter((i) => i?.ownerUsername && i.ownerUsername.toLowerCase() === reqLower)
      : [],
    userAlbums: reqLower
      ? (data.userAlbums || []).filter((a) => a?.ownerUsername && a.ownerUsername.toLowerCase() === reqLower)
      : [],
    userPhotocards: reqLower
      ? (data.userPhotocards || []).filter((pc) => pc?.ownerUsername && pc.ownerUsername.toLowerCase() === reqLower)
      : [],
    magazines: data.magazines || [],
    releases: data.releases || [],
    awards: data.awards || [],
    userAwardVotes: reqLower
      ? Object.fromEntries(Object.entries(data.userAwardVotes || {}).filter(([k]) => k.toLowerCase().startsWith(`${reqLower}_`)))
      : {},
    userVotedNominees: reqLower
      ? Object.fromEntries(Object.entries(data.userVotedNominees || {}).filter(([k]) => k.toLowerCase().startsWith(`${reqLower}_`)))
      : {},
    auditions: isPrivileged ? (data.auditions || []) : (reqLower ? (data.auditions || []).filter((a) => a.applicantUsername?.toLowerCase() === reqLower) : []),
    auditionPassCodes: isPrivileged ? (data.auditionPassCodes || []) : [],
    notifications: safeNotifications,
    tradeOffers: reqLower ? (data.tradeOffers || []).filter((t) => t.proposerUsername?.toLowerCase() === reqLower || t.targetUsername?.toLowerCase() === reqLower) : [],
    ceoRequests: isPrivileged ? (data.ceoRequests || []) : (reqLower ? (data.ceoRequests || []).filter((r) => r.username?.toLowerCase() === reqLower) : []),
    partners: data.partners || [],
    charts: data.charts || [],
    reviews: data.reviews || {},
    adminDelegations: isPrivileged ? (data.adminDelegations || {}) : {},
    adminAuditLog: isPrivileged ? (data.adminAuditLog || []) : [],
    userRequests: isPrivileged ? (data.userRequests || []) : (reqLower ? (data.userRequests || []).filter((r) => r.username?.toLowerCase() === reqLower) : []),
    achievements: data.achievements || [],
    calendarEvents: data.calendarEvents || [],
    penaltiesHistory: (isPrivileged || isModerator) ? (data.penaltiesHistory || []) : (reqLower ? (data.penaltiesHistory || []).filter((p) => p.targetUsername?.toLowerCase() === reqLower) : []),
    collaborations: data.collaborations || [],
    followers: data.followers || [],
    userStatuses: safeStatuses,
    postReactions: data.postReactions || {},
    commentReactions: data.commentReactions || {},
    savedCollections: reqKey ? { [reqKey]: (savedColKey && data.savedCollections?.[savedColKey]) || [] } : {},
    savedPosts: reqKey ? { [reqKey]: (savedPostsKey && data.savedPosts?.[savedPostsKey]) || [] } : {},
    vendors: (data.vendors || []).filter((v) => v.status === 'aprobado' || (reqLower && v.username?.toLowerCase() === reqLower) || isPrivileged),
    inventoryMovements: isPrivileged ? (data.inventoryMovements || []) : [],
    discountCoupons: (data.discountCoupons || []).filter((c) => c.isActive),
    lastUpdated: data.lastUpdated
  };
}

let db = loadDatabase();

// Centralized Ledger Recorder Helper
function recordLedger(entry: {
  username: string;
  type: 'earn_coins' | 'earn_gems' | 'spend_coins' | 'spend_gems' | 'transfer_gems_sent' | 'transfer_gems_received';
  currency: 'coins' | 'gems';
  amount: number;
  balanceAfter: number;
  reason: string;
  relatedUser?: string;
}) {
  if (!Array.isArray(db.economyLedger)) db.economyLedger = [];
  const ledgerItem = {
    id: 'tx-' + Date.now() + '-' + Math.floor(Math.random() * 10000),
    ...entry,
    timestamp: new Date().toISOString()
  };
  db.economyLedger.unshift(ledgerItem);
  return ledgerItem;
}

// ==========================================
// API ROUTES
// ==========================================

app.get('/api/health', async (_req, res) => {
  const persistenceCfg = getSupabasePersistenceConfig();
  const metrics = getSupabasePersistenceMetrics();
  const supaServerStatus = getSupabaseStatus();
  const supabaseConfigured = persistenceCfg.configured;
  const supabaseReachable = supabaseConfigured ? await checkSupabaseReachable() : false;
  const updatedMetrics = getSupabasePersistenceMetrics();

  let driver = 'local-json-atomic';
  if (supabaseConfigured && supabaseReachable) {
    driver = 'supabase-app-state+local-backup';
  } else if (supabaseConfigured) {
    driver = 'local-json-fallback (supabase-unreachable)';
  }

  const warningMessage =
    lastPersistenceWarning ||
    (!supabaseConfigured
      ? 'Almacenamiento local en data/db.json con respaldo en data/backups/backup_latest.json (Supabase no configurado en .env).'
      : !supabaseReachable
        ? `Supabase configurado pero inalcanzable (${updatedMetrics.lastError || 'error de conexión'}). Operando con respaldo local data/db.json.`
        : null);

  res.json({
    status: 'ok',
    service: 'ym-ki-records',
    time: new Date().toISOString(),
    uptimeSeconds: Math.floor((Date.now() - SERVER_START_TIME) / 1000),
    registeredUsersCount: Object.keys(db.allProfiles || {}).length,
    supabaseConfigured,
    supabaseReachable,
    lastSupabaseWriteAt: updatedMetrics.lastSuccessfulWriteAt || metrics.lastSuccessfulWriteAt,
    persistence: {
      driver,
      dbFileExists: fs.existsSync(DB_FILE),
      backupExists: fs.existsSync(BACKUP_FILE),
      supabaseConfigured,
      supabaseReachable,
      lastSupabaseWriteAt: updatedMetrics.lastSuccessfulWriteAt || metrics.lastSuccessfulWriteAt,
      supabase: {
        configured: supaServerStatus.configured || supabaseConfigured,
        hasPublishableKey: supaServerStatus.hasPublishableKey,
        hasSecretKey: supaServerStatus.hasSecretKey,
        hasJwks: supaServerStatus.hasJwks
      },
      warning: warningMessage
    }
  });
});

// @supabase/server Verification & Identity Endpoints
app.get('/api/supabase/verify', requireSupabaseAuth(['user', 'publishable', 'secret']), (req, res) => {
  const ctx = (req as any).supabaseContext;
  res.json({
    authenticated: true,
    authMode: ctx.auth.authMode,
    keyName: ctx.auth.keyName || null,
    userClaims: ctx.auth.userClaims || null,
    clients: {
      hasRlsClient: Boolean(ctx.supabase),
      hasAdminClient: Boolean(ctx.supabaseAdmin)
    }
  });
});

app.get('/api/supabase/me', requireSupabaseAuth('user'), (req, res) => {
  const ctx = (req as any).supabaseContext;
  res.json({
    user: ctx.auth.userClaims,
    claims: ctx.auth.jwtClaims
  });
});

// Sanitized Public & Authorized State Endpoint
app.get('/api/state', (req, res) => {
  const user = (req as any).user?.username;
  res.json(getPublicState(db, user));
});

// State Synchronization: Strictly restricted to Authenticated Administrators & Founders
app.post('/api/sync', requireRole(['admin']), (req, res) => {
  const updates = req.body;
  if (updates && typeof updates === 'object') {
    const allowedKeys = [
      'survivals', 'forums', 'posts', 'fanClubs', 'products',
      'magazines', 'releases', 'awards', 'partners', 'charts',
      'calendarEvents', 'achievements', 'collaborations'
    ];
    for (const key of allowedKeys) {
      if (updates[key] !== undefined) {
        (db as any)[key] = updates[key];
      }
    }
    appendAuditLog(db, {
      adminUsername: (req as any).user.username,
      action: 'ADMIN_STATE_SYNC',
      details: 'Sincronización administrativa de colecciones autorizadas.'
    });
    sanitizeDb(db);
    saveDatabase(db);
  }
  res.json({ success: true, message: 'Estado sincronizado por administración autorizada.' });
});

// ==========================================
// 5. MULTIMEDIA — DIRECT FILE UPLOAD ENDPOINT
// ==========================================
app.post('/api/upload', requireAuth, async (req, res) => {
  try {
    const { fileData, fileName, fileType } = req.body;
    if (!fileData || typeof fileData !== 'string') {
      return res.status(400).json({ error: 'No se recibió ningún contenido de archivo.' });
    }

    // Parse data URL if applicable
    const matches = fileData.match(/^data:([A-Za-z0-9\-+\/.]+);base64,(.+)$/);
    let buffer: Buffer;
    let mime = (fileType || '').toLowerCase();

    if (matches && matches.length === 3) {
      mime = matches[1].toLowerCase();
      buffer = Buffer.from(matches[2], 'base64');
    } else {
      buffer = Buffer.from(fileData, 'base64');
    }

    // Strict 15MB limit
    if (buffer.length > 15 * 1024 * 1024) {
      return res.status(400).json({ error: 'El archivo excede el límite máximo de 15MB.' });
    }

    // Allowed mime types
    const allowedMimes: Record<string, string> = {
      'image/png': '.png',
      'image/jpeg': '.jpg',
      'image/jpg': '.jpg',
      'image/webp': '.webp',
      'image/gif': '.gif',
      'video/mp4': '.mp4',
      'video/webm': '.webm',
      'audio/mpeg': '.mp3',
      'audio/mp3': '.mp3',
      'audio/wav': '.wav',
      'audio/ogg': '.ogg'
    };

    if (!allowedMimes[mime]) {
      return res.status(400).json({ error: 'Formato de archivo no admitido. Solo se admiten imágenes, audio y video válidos.' });
    }

    // Magic bytes verification
    let isValidMagic = false;
    if (mime.includes('png') && buffer.length >= 8 && buffer[0] === 0x89 && buffer[1] === 0x50 && buffer[2] === 0x4E && buffer[3] === 0x47) {
      isValidMagic = true;
    } else if ((mime.includes('jpeg') || mime.includes('jpg')) && buffer.length >= 3 && buffer[0] === 0xFF && buffer[1] === 0xD8 && buffer[2] === 0xFF) {
      isValidMagic = true;
    } else if (mime.includes('gif') && buffer.length >= 6 && buffer.toString('ascii', 0, 4) === 'GIF8') {
      isValidMagic = true;
    } else if (mime.includes('webp') && buffer.length >= 12 && buffer.toString('ascii', 0, 4) === 'RIFF' && buffer.toString('ascii', 8, 12) === 'WEBP') {
      isValidMagic = true;
    } else if (mime.includes('mp4') && buffer.length >= 12 && buffer.toString('ascii', 4, 8) === 'ftyp') {
      isValidMagic = true;
    } else if (mime.includes('webm') && buffer.length >= 4 && buffer[0] === 0x1A && buffer[1] === 0x45 && buffer[2] === 0xDF && buffer[3] === 0xA3) {
      isValidMagic = true;
    } else if (mime.includes('wav') && buffer.length >= 12 && buffer.toString('ascii', 0, 4) === 'RIFF' && buffer.toString('ascii', 8, 12) === 'WAVE') {
      isValidMagic = true;
    } else if (mime.includes('ogg') && buffer.length >= 4 && buffer.toString('ascii', 0, 4) === 'OggS') {
      isValidMagic = true;
    } else if ((mime.includes('mp3') || mime.includes('mpeg')) && buffer.length >= 3) {
      if (buffer.toString('ascii', 0, 3) === 'ID3' || (buffer[0] === 0xFF && (buffer[1] & 0xE0) === 0xE0)) {
        isValidMagic = true;
      }
    }

    if (!isValidMagic) {
      return res.status(400).json({ error: 'La firma del archivo no coincide con su tipo. Archivo rechazado por seguridad.' });
    }

    const ext = allowedMimes[mime] || '.png';
    const safeBaseName = (path.basename(fileName || 'upload', ext) || 'file')
      .replace(/[^a-zA-Z0-9_\-]/g, '_')
      .slice(0, 30);
    const uniqueFileName = `${safeBaseName}_${Date.now()}_${Math.floor(Math.random() * 10000)}${ext}`;

    // Prefer Supabase Storage bucket "uploads" when configured; fall back to local public/uploads
    if (getSupabasePersistenceConfig().configured) {
      const uploaded = await uploadBufferToSupabaseStorage(uniqueFileName, buffer, mime, 'uploads');
      if (uploaded.url) {
        return res.json({
          success: true,
          url: uploaded.url,
          fileName: uniqueFileName,
          size: buffer.length,
          mimeType: mime
        });
      }
      console.warn('Supabase Storage upload fallback to local disk:', uploaded.error || 'unknown error');
    }

    const destinationPath = path.join(uploadsDir, uniqueFileName);
    fs.writeFileSync(destinationPath, buffer);

    return res.json({
      success: true,
      url: `${(process.env.PUBLIC_SERVER_URL || '').trim().replace(/\/$/, '')}/uploads/${uniqueFileName}`,
      fileName: uniqueFileName,
      size: buffer.length,
      mimeType: mime
    });
  } catch (err: any) {
    console.error('Upload error:', err);
    return res.status(500).json({ error: 'Error procesando la carga del archivo.' });
  }
});

// ==========================================
// 6. AUTHENTICATION, LOGIN, RECOVERY & SESSIONS
// ==========================================

app.post('/api/auth/login', (req, res) => {
  const { identifier, password } = req.body;
  const cleanId = String(identifier || '').trim();
  if (!cleanId || !password) {
    return res.status(400).json({ error: 'Debes proporcionar tu nombre de usuario o correo y contraseña.' });
  }

  const rlKey = buildRateLimitKey(req.ip, cleanId);
  const rl = checkRateLimitStatus(db.loginAttempts, rlKey);
  if (!rl.allowed) {
    return res.status(429).json({
      error: 'Demasiados intentos fallidos. Por seguridad el acceso está temporalmente bloqueado durante 2 minutos.'
    });
  }

  // Canonicalize usernames & email lookup
  let canonicalUser: string | null = null;
  const lowerNoSpaces = cleanId.toLowerCase().replace(/[\s_-]+/g, '');
  const match = Object.keys(db.allProfiles).find(
    (u) =>
      u.toLowerCase() === cleanId.toLowerCase() ||
      u.toLowerCase().replace(/[\s_-]+/g, '') === lowerNoSpaces ||
      (db.allProfiles[u]?.email && db.allProfiles[u].email.toLowerCase() === cleanId.toLowerCase())
  );
  if (match) canonicalUser = match;

  const profile = canonicalUser ? db.allProfiles[canonicalUser] : null;
  const cred = canonicalUser ? db.userCredentials[canonicalUser] : null;

  if (!profile || !canonicalUser) {
    recordFailedRateLimitAttempt(db.loginAttempts, rlKey);
    saveDatabase(db);
    return res.status(401).json({ error: 'Usuario o contraseña incorrectos.' });
  }

  if (!cred || !cred.hash || !cred.salt || profile.credentialsPendingRecovery) {
    return res.status(403).json({
      error: 'Esta cuenta se encuentra pendiente de recuperación de credenciales. Usa la opción "Recuperar" con un código emitido por administración.'
    });
  }

  const susp = evaluateSuspension(profile);
  if (susp.expired) {
    clearExpiredSuspension(profile, db.penaltiesHistory, canonicalUser);
  } else if (susp.suspended) {
    return res.status(403).json({
      error: `Tu cuenta está suspendida (${susp.expires === 'permanente' ? 'permanente' : 'temporal'}). Motivo: ${susp.reason}`
    });
  }

  const cleanPass = String(password).trim();
  const isValid = verifyPassword(cleanPass, cred.salt, cred.hash);

  if (!isValid) {
    recordFailedRateLimitAttempt(db.loginAttempts, rlKey);
    saveDatabase(db);
    return res.status(401).json({
      error: 'Usuario o contraseña incorrectos.'
    });
  }

  clearRateLimitAttempt(db.loginAttempts, rlKey);
  clearRateLimitAttempt(db.loginAttempts, buildRateLimitKey(req.ip, canonicalUser));
  cred.lastLogin = new Date().toISOString();

  // Generate cryptographically secure session token
  const token = crypto.randomBytes(32).toString('hex');
  if (!db.activeSessions) db.activeSessions = {};
  db.activeSessions[token] = {
    token,
    username: canonicalUser,
    createdAt: Date.now(),
    expiresAt: Date.now() + 7 * 24 * 60 * 60 * 1000,
    ip: req.ip
  };

  appendAuditLog(db, {
    adminUsername: canonicalUser,
    action: 'USER_LOGIN',
    details: `Inicio de sesión autenticado como @${canonicalUser}`
  });

  saveDatabase(db);

  const safeProfiles = getSafeProfiles(db, canonicalUser);
  return res.json({
    success: true,
    token,
    username: canonicalUser,
    profile: safeProfiles[canonicalUser] || profile,
    isFounder: !!profile.isFounder,
    firstRegisteredUser: db.firstRegisteredUser || ''
  });
});

// User Registration: Grants admin/founder to the first user registering on the server; strictly 'fan' thereafter
app.post('/api/auth/register', (req, res) => {
  console.log('[POST /api/auth/register] Petición recibida:', {
    method: req.method,
    path: req.originalUrl,
    origin: req.headers.origin || 'same-origin',
    referer: req.headers.referer || 'none',
    host: req.headers.host || 'unknown',
    contentType: req.headers['content-type'] || 'none',
    hasBody: Boolean(req.body && typeof req.body === 'object' && Object.keys(req.body).length > 0)
  });

  const { username, nickname, email, dob, password, acceptedTerms } = req.body || {};
  const cleanUsername = String(username || '').trim();

  if (!cleanUsername) {
    return sendApiError(res, 400, 'Nombre de usuario requerido.');
  }

  if (!isValidUsername(cleanUsername)) {
    return res.status(400).json({ error: 'El nombre de usuario debe tener entre 3 y 20 caracteres válidos (letras, números, puntos o guiones).' });
  }

  if (!email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(String(email).trim())) {
    return res.status(400).json({ error: 'Debes proporcionar un correo electrónico válido.' });
  }

  if (!password || String(password).trim().length < 6) {
    return res.status(400).json({ error: 'La contraseña debe tener al menos 6 caracteres seguros.' });
  }

  if (!acceptedTerms) {
    return res.status(400).json({ error: 'Debes aceptar los Términos de Servicio y la Política de Privacidad para registrarte.' });
  }

  const lower = cleanUsername.toLowerCase();
  if (isReservedUsername(lower)) {
    return res.status(403).json({
      error: 'Este nombre de usuario está reservado para la dirección oficial de YM-ki Records.'
    });
  }

  const isTaken = Object.keys(db.allProfiles).some((u) => u.trim().toLowerCase() === lower);
  if (isTaken) {
    return res.status(400).json({ error: 'Ese nombre de usuario ya está registrado por otra persona. Por favor elige otro.' });
  }

  const normalizedEmail = String(email).trim().toLowerCase();
  const emailTaken = Object.values(db.allProfiles).some(
    (p: any) => p?.email && String(p.email).trim().toLowerCase() === normalizedEmail
  );
  if (emailTaken) {
    return res.status(400).json({ error: 'Este correo electrónico ya está asociado a otra cuenta.' });
  }

  const isFirstServerAdmin = shouldAssignFirstServerAdmin(db.allProfiles, db.firstRegisteredUser);

  const profile = {
    username: cleanUsername,
    nickname: (nickname || cleanUsername).trim(),
    email: normalizedEmail,
    avatar: 'https://images.unsplash.com/photo-1534528741775-53994a69daeb?w=150&h=150&fit=crop&crop=faces',
    banner: 'https://images.unsplash.com/photo-1514525253161-7a46d19cd819?w=900&h=300&fit=crop',
    description: isFirstServerAdmin
      ? 'Fundador y Administrador Principal de YM-ki Records.'
      : 'Miembro oficial de la comunidad YM-ki Records.',
    ringColor: isFirstServerAdmin ? '#eab308' : '#6366f1',
    transparentFrame: null,
    accountType: isFirstServerAdmin ? 'admin' : 'fan',
    isFounder: isFirstServerAdmin,
    accessStatus: 'active',
    profileBgColor: isFirstServerAdmin ? '#0f172a' : '#1e293b',
    badgeAdminColor: '#ec4899',
    badgeVerifiedColor: '#38bdf8',
    animal: 'Zorro 🦊',
    allowMessages: true,
    coins: isFirstServerAdmin ? 999999 : 500,
    gems: isFirstServerAdmin ? 9999 : 10,
    dob: dob || '2004-06-15',
    isMerchPrivate: false,
    showcaseItemIds: [],
    completedMissions: [],
    fandomDisplayMode: 'beside_username',
    displayedFandomTags: [],
    ownedFrames: isFirstServerAdmin ? ['frame-cyber-neon', 'frame-gold-star', 'frame-prism-diamond'] : [],
    selectedFrameId: isFirstServerAdmin ? 'frame-gold-star' : null,
    customFrameColor: isFirstServerAdmin ? '#eab308' : '#6366f1',
    idCard: {
      pseudonym: cleanUsername,
      age: 20,
      gender: 'Femenino',
      matricula: `YM-${new Date().getFullYear()}-${Math.floor(1000 + Math.random() * 9000)}`,
      faceclaim: 'https://images.unsplash.com/photo-1534528741775-53994a69daeb?w=150&h=150&fit=crop&crop=faces',
      cardColor: isFirstServerAdmin ? '#000000' : '#6366f1',
      stripeColor: '#ec4899',
      specialties: ['vocal']
    }
  };

  db.allProfiles[cleanUsername] = profile;

  const cred = hashPassword(String(password).trim());
  db.userCredentials[cleanUsername] = { ...cred, isFounder: isFirstServerAdmin };
  if (isFirstServerAdmin) {
    db.firstRegisteredUser = cleanUsername;
  }
  db.registeredUsersCount = Object.keys(db.allProfiles).length;

  const token = crypto.randomBytes(32).toString('hex');
  if (!db.activeSessions) db.activeSessions = {};
  db.activeSessions[token] = {
    token,
    username: cleanUsername,
    createdAt: Date.now(),
    expiresAt: Date.now() + 7 * 24 * 60 * 60 * 1000,
    ip: req.ip
  };

  saveDatabase(db);

  const safeProfiles = getSafeProfiles(db, cleanUsername);
  return res.json({
    success: true,
    token,
    username: cleanUsername,
    profile: safeProfiles[cleanUsername] || profile,
    isFounder: !!profile.isFounder,
    firstRegisteredUser: db.firstRegisteredUser || '',
    message: isFirstServerAdmin
      ? '¡Bienvenido Fundador! Tu cuenta ha sido creada con permisos de Administrador.'
      : '¡Bienvenido a YM-ki Records! Tu cuenta ha sido creada exitosamente.'
  });
});

// Authenticated User Identity Endpoint
app.get('/api/auth/me', requireAuth, (req, res) => {
  const user = (req as any).user;
  const safeProfiles = getSafeProfiles(db, user.username);
  const profile = safeProfiles[user.username] || db.allProfiles[user.username];
  res.json({
    success: true,
    user: {
      username: user.username,
      accountType: user.accountType,
      isFounder: user.isFounder
    },
    profile
  });
});

// Change Password Endpoint: verifies current password, updates hash, revokes OTHER sessions
app.post('/api/auth/change-password', requireAuth, (req, res) => {
  const user = (req as any).user;
  const { currentPassword, newPassword } = req.body;

  if (!currentPassword || !newPassword || String(newPassword).trim().length < 6) {
    return res.status(400).json({ error: 'Debes ingresar tu contraseña actual y una nueva de al menos 6 caracteres.' });
  }

  const cred = db.userCredentials[user.username];
  if (!cred || !cred.hash || !cred.salt) {
    return res.status(400).json({ error: 'Credenciales de usuario no encontradas en el servidor.' });
  }

  const isCurrentValid = verifyPassword(String(currentPassword).trim(), cred.salt, cred.hash);
  if (!isCurrentValid) {
    return res.status(401).json({ error: 'La contraseña actual no coincide.' });
  }

  const newCred = hashPassword(String(newPassword).trim());
  db.userCredentials[user.username] = {
    ...newCred,
    isFounder: !!user.isFounder
  };
  if (db.allProfiles[user.username]) {
    delete db.allProfiles[user.username].credentialsPendingRecovery;
    db.allProfiles[user.username].accessStatus = 'active';
  }

  // Revoke all other active sessions, keeping current token active
  revokeUserSessions(db.activeSessions, user.username, user.token);
  saveDatabase(db);
  return res.json({ success: true, message: 'Tu contraseña ha sido actualizada con éxito y se cerraron las demás sesiones.' });
});

// Password recovery: Never reveal whether account exists; rate-limited; stores hashed single-use token
app.post('/api/auth/forgot-password', (req, res) => {
  const { identifier } = req.body;
  const cleanId = String(identifier || '').trim().toLowerCase();
  if (!cleanId) {
    return res.status(400).json({ error: 'Usuario o correo requerido.' });
  }

  const rlKey = buildRateLimitKey(req.ip, `forgot:${cleanId}`);
  const rl = checkRateLimitStatus(db.loginAttempts, rlKey);
  if (!rl.allowed) {
    return res.status(429).json({
      error: 'Demasiadas solicitudes de recuperación. Espera 2 minutos antes de intentar de nuevo.'
    });
  }
  recordFailedRateLimitAttempt(db.loginAttempts, rlKey);

  const matchedUser = Object.keys(db.allProfiles).find(
    (u) => u.toLowerCase() === cleanId || db.allProfiles[u]?.email?.toLowerCase() === cleanId
  );

  if (matchedUser) {
    const { record } = createRecoveryTokenRecord(Date.now(), 15 * 60 * 1000, 'self-request');
    if (!db.passwordResetTokens) db.passwordResetTokens = {};
    db.passwordResetTokens[matchedUser] = record;

    // Notify founder/admin queue privately without leaking existence to caller
    const adminRecipient = db.firstRegisteredUser || Object.keys(db.allProfiles).find((u) => db.allProfiles[u]?.accountType === 'admin' || db.allProfiles[u]?.isFounder);
    if (adminRecipient) {
      if (!Array.isArray(db.notifications)) db.notifications = [];
      db.notifications.unshift({
        id: 'notif-rec-' + Date.now(),
        recipient: adminRecipient,
        type: 'system',
        category: 'cuenta',
        title: '🔐 Solicitud de Recuperación de Cuenta',
        message: `@${matchedUser} solicitó recuperación de contraseña. Emite un código de un solo uso desde el panel administrativo si procede.`,
        date: new Date().toISOString(),
        read: false
      });
    }
  }

  saveDatabase(db);
  return res.json({
    success: true,
    message: 'Si los datos coinciden con una cuenta registrada, se ha procesado tu solicitud de recuperación. Utiliza tu código de recuperación de un solo uso (válido por 15 minutos) para establecer una nueva contraseña.'
  });
});

// Authenticated Admin/Founder issues a single-use recovery code for a user without knowing/setting their password
app.post('/api/admin/recovery-token', requireAuth, requireRole(['admin']), (req, res) => {
  const adminUser = (req as any).user;
  const { targetUsername } = req.body;
  const targetKey = resolveUsernameKey(db.allProfiles, targetUsername);
  if (!targetKey) {
    return res.status(404).json({ error: 'Usuario no encontrado.' });
  }
  if (db.allProfiles[targetKey]?.isFounder && !adminUser.isFounder) {
    return res.status(403).json({ error: 'Solo el CEO Fundador puede emitir un código de recuperación para la cuenta fundadora.' });
  }

  const { rawToken, record } = createRecoveryTokenRecord(Date.now(), 15 * 60 * 1000, adminUser.username);
  if (!db.passwordResetTokens) db.passwordResetTokens = {};
  db.passwordResetTokens[targetKey] = record;

  appendAuditLog(db, {
    adminUsername: adminUser.username,
    action: 'ISSUE_RECOVERY_TOKEN',
    targetUser: targetKey,
    details: `Generó un código de recuperación de un solo uso (expira en 15 min) para @${targetKey}`
  });

  saveDatabase(db);
  res.json({
    success: true,
    targetUsername: targetKey,
    recoveryCode: rawToken,
    expiresAt: new Date(record.expiresAt).toISOString(),
    message: `Código de recuperación generado para @${targetKey}. Compártelo por un canal privado seguro (expira en 15 minutos).`
  });
});

app.post('/api/auth/reset-password', (req, res) => {
  const { username, newPassword, resetToken } = req.body;
  const cleanUser = String(username || '').trim();
  if (!cleanUser || !newPassword || String(newPassword).trim().length < 6) {
    return res.status(400).json({ error: 'Datos de restablecimiento incompletos o contraseña menor a 6 caracteres.' });
  }

  const rlKey = buildRateLimitKey(req.ip, `reset:${cleanUser}`);
  const rl = checkRateLimitStatus(db.loginAttempts, rlKey);
  if (!rl.allowed) {
    return res.status(429).json({
      error: 'Demasiados intentos de restablecimiento. Espera 2 minutos antes de intentar de nuevo.'
    });
  }

  const targetKey = resolveUsernameKey(db.allProfiles, cleanUser);
  const authUser = (req as any).user;
  const isAuthorizedSession =
    authUser &&
    targetKey &&
    (authUser.isFounder ||
      (authUser.accountType === 'admin' && !db.allProfiles[targetKey]?.isFounder) ||
      authUser.username.toLowerCase() === targetKey.toLowerCase());

  const tokenRecord = targetKey ? db.passwordResetTokens?.[targetKey] : undefined;
  const hasValidResetToken = Boolean(
    targetKey && resetToken && verifyRecoveryToken(tokenRecord, String(resetToken))
  );

  if (!targetKey || (!isAuthorizedSession && !hasValidResetToken)) {
    recordFailedRateLimitAttempt(db.loginAttempts, rlKey);
    saveDatabase(db);
    return res.status(401).json({
      error: 'Código de recuperación o autorización inválidos o expirados.'
    });
  }

  clearRateLimitAttempt(db.loginAttempts, rlKey);
  if (db.passwordResetTokens?.[targetKey]) {
    delete db.passwordResetTokens[targetKey];
  }

  const newCred = hashPassword(String(newPassword).trim());
  db.userCredentials[targetKey] = {
    ...newCred,
    isFounder: !!db.allProfiles[targetKey]?.isFounder
  };
  delete db.allProfiles[targetKey].credentialsPendingRecovery;
  db.allProfiles[targetKey].accessStatus = 'active';

  // Revoke ALL active sessions for this user upon password reset
  const revokedCount = revokeUserSessions(db.activeSessions, targetKey);

  appendAuditLog(db, {
    adminUsername: authUser?.username || targetKey,
    action: 'PASSWORD_RESET',
    targetUser: targetKey,
    details: `Contraseña restablecida (${hasValidResetToken ? 'token de recuperación' : 'sesión autorizada'}). Sesiones revocadas: ${revokedCount}.`
  });

  saveDatabase(db);
  return res.json({
    success: true,
    revokedSessions: revokedCount,
    message: 'Contraseña restablecida exitosamente. Todas las sesiones anteriores fueron cerradas.'
  });
});

// Logout Session Endpoint
app.post('/api/auth/logout', (req, res) => {
  const token = extractBearerToken(req);
  if (token && db.activeSessions && db.activeSessions[token]) {
    delete db.activeSessions[token];
    saveDatabase(db);
  }
  res.json({ success: true, message: 'Sesión cerrada exitosamente.' });
});

// Logout all devices
app.post('/api/auth/logout-all', requireAuth, (req, res) => {
  const user = (req as any).user;
  const removed = revokeUserSessions(db.activeSessions, user.username);
  saveDatabase(db);
  res.json({ success: true, revokedSessions: removed, message: 'Todas las sesiones han sido cerradas en todos los dispositivos.' });
});

// Username Change Endpoint: Authenticated, updates sessions and related records cleanly
app.post('/api/auth/change-username', requireAuth, (req, res) => {
  const authUser = (req as any).user;
  const { currentUsername, newUsername } = req.body;
  const oldClean = (currentUsername || authUser.username || '').trim();
  const newClean = (newUsername || '').trim();

  if (!oldClean || !newClean) {
    return res.status(400).json({ error: 'Debes proporcionar tu nombre de usuario actual y el nuevo.' });
  }

  if (oldClean.toLowerCase() !== authUser.username.toLowerCase() && !authUser.isFounder) {
    return res.status(403).json({ error: 'Solo puedes cambiar tu propio nombre de usuario.' });
  }

  const reservedFounders = ['ceo_miki', 'ceo_yako', 'ceo miki', 'ceo yako', 'miki', 'yako', 'admin', 'administrador', 'administracion', 'ymki'];
  if (reservedFounders.includes(newClean.toLowerCase())) {
    return res.status(403).json({ error: 'No puedes utilizar un nombre reservado.' });
  }

  if (newClean.length < 3 || newClean.length > 25) {
    return res.status(400).json({ error: 'El nombre de usuario debe tener entre 3 y 25 caracteres.' });
  }

  const isTaken = Object.keys(db.allProfiles).some(
    (u) => u.trim().toLowerCase() === newClean.toLowerCase() && u.trim().toLowerCase() !== oldClean.toLowerCase()
  );
  if (isTaken) {
    return res.status(400).json({ error: `El nombre de usuario "${newClean}" ya está en uso.` });
  }

  const existingKey = Object.keys(db.allProfiles).find((u) => u.toLowerCase() === oldClean.toLowerCase()) || oldClean;
  const profile = db.allProfiles[existingKey];
  if (!profile) {
    return res.status(404).json({ error: 'Perfil no encontrado.' });
  }

  profile.username = newClean;
  if (profile.idCard) profile.idCard.pseudonym = newClean;
  delete db.allProfiles[existingKey];
  db.allProfiles[newClean] = profile;

  // Move credentials
  if (db.userCredentials[existingKey]) {
    db.userCredentials[newClean] = db.userCredentials[existingKey];
    delete db.userCredentials[existingKey];
  }

  // Update active sessions pointing to old username so token remains valid!
  if (db.activeSessions) {
    for (const sess of Object.values(db.activeSessions)) {
      if (sess.username.toLowerCase() === existingKey.toLowerCase()) {
        sess.username = newClean;
      }
    }
  }

  // Update firstRegisteredUser and keyed maps
  if (db.firstRegisteredUser && db.firstRegisteredUser.toLowerCase() === existingKey.toLowerCase()) {
    db.firstRegisteredUser = newClean;
  }
  const renameMapKey = (mapObj?: Record<string, any>) => {
    if (mapObj && mapObj[existingKey] !== undefined) {
      mapObj[newClean] = mapObj[existingKey];
      delete mapObj[existingKey];
    }
  };
  renameMapKey(db.userStatuses);
  if (db.userStatuses?.[newClean]) db.userStatuses[newClean].username = newClean;
  renameMapKey(db.blockedUsers);
  renameMapKey(db.wishlists);
  renameMapKey(db.showcaseCollections);
  renameMapKey(db.savedCollections);
  renameMapKey(db.savedPosts);
  renameMapKey(db.missionProgress);
  renameMapKey(db.adminDelegations);

  if (Array.isArray(db.inventory)) {
    for (const item of db.inventory) {
      if (item.ownerUsername === existingKey) item.ownerUsername = newClean;
    }
  }
  if (Array.isArray(db.productPurchases)) {
    for (const pur of db.productPurchases) {
      if (pur.buyerUsername === existingKey) pur.buyerUsername = newClean;
    }
  }
  if (Array.isArray(db.followers)) {
    for (const f of db.followers) {
      if (f.followerUsername === existingKey) f.followerUsername = newClean;
      if (f.followingUsername === existingKey) f.followingUsername = newClean;
    }
  }
  if (Array.isArray(db.vendors)) {
    for (const v of db.vendors) {
      if (v.username === existingKey) v.username = newClean;
    }
  }

  saveDatabase(db);
  const safeProfile = getSafeProfiles(db, newClean)[newClean] || profile;
  return res.json({ success: true, newUsername: newClean, profile: safeProfile });
});

// ==========================================
// 1. VIRTUAL ECONOMY — MISSIONS & GEMS TRANSFER
// ==========================================

// Get missions
app.get('/api/missions', (req, res) => {
  res.json({ success: true, missions: db.missions || [] });
});

// Create mission (Admin only)
app.post('/api/missions', requireAuth, requireRole(['admin']), (req, res) => {
  const adminUser = (req as any).user.username;
  const { title, description, category, reqType, targetCount, rewardCoins, rewardGems, isActive } = req.body;
  if (!title || !category || !reqType) {
    return res.status(400).json({ error: 'Campos requeridos incompletos para crear la misión.' });
  }

  const newMission = {
    id: 'm-' + Date.now(),
    title: String(title).trim(),
    description: String(description || '').trim(),
    category: category || 'daily',
    reqType: reqType || 'publish_posts',
    targetCount: Math.max(1, Number(targetCount) || 1),
    rewardCoins: Math.max(0, Number(rewardCoins) || 0),
    rewardGems: Math.max(0, Number(rewardGems) || 0),
    isActive: isActive !== false,
    createdAt: new Date().toISOString()
  };

  if (!Array.isArray(db.missions)) db.missions = [];
  db.missions.push(newMission);
  appendAuditLog(db, {
    adminUsername: adminUser,
    action: 'CREATE_MISSION',
    details: `Creó misión "${newMission.title}" (${newMission.category})`
  });
  saveDatabase(db);
  res.json({ success: true, mission: newMission, missions: db.missions });
});

// Update mission (Admin only)
app.put('/api/missions/:id', requireAuth, requireRole(['admin']), (req, res) => {
  const adminUser = (req as any).user.username;
  const { id } = req.params;
  const mission = (db.missions || []).find((m: any) => m.id === id);
  if (!mission) return res.status(404).json({ error: 'Misión no encontrada.' });

  const { title, description, category, reqType, targetCount, rewardCoins, rewardGems, isActive } = req.body;
  if (title !== undefined) mission.title = String(title).trim();
  if (description !== undefined) mission.description = String(description).trim();
  if (category !== undefined) mission.category = category;
  if (reqType !== undefined) mission.reqType = reqType;
  if (targetCount !== undefined) mission.targetCount = Math.max(1, Number(targetCount) || 1);
  if (rewardCoins !== undefined) mission.rewardCoins = Math.max(0, Number(rewardCoins) || 0);
  if (rewardGems !== undefined) mission.rewardGems = Math.max(0, Number(rewardGems) || 0);
  if (isActive !== undefined) mission.isActive = Boolean(isActive);

  appendAuditLog(db, {
    adminUsername: adminUser,
    action: 'UPDATE_MISSION',
    details: `Actualizó misión "${mission.title}"`
  });
  saveDatabase(db);
  res.json({ success: true, mission, missions: db.missions });
});

// Delete mission (Admin only)
app.delete('/api/missions/:id', requireAuth, requireRole(['admin']), (req, res) => {
  const adminUser = (req as any).user.username;
  const { id } = req.params;
  const target = (db.missions || []).find((m: any) => m.id === id);
  db.missions = (db.missions || []).filter((m: any) => m.id !== id);
  if (target) {
    appendAuditLog(db, {
      adminUsername: adminUser,
      action: 'DELETE_MISSION',
      details: `Eliminó misión "${target.title}"`
    });
  }
  saveDatabase(db);
  res.json({ success: true, missions: db.missions });
});

// Track user activity towards mission requirements
app.post('/api/missions/track-action', requireAuth, (req, res) => {
  const authUser = (req as any).user.username;
  const { username, actionType, count } = req.body;
  if (!actionType) return res.status(400).json({ error: 'Datos incompletos.' });
  if (username && username.toLowerCase() !== authUser.toLowerCase() && !isAdminOrFounder((req as any).user)) {
    return res.status(403).json({ error: 'No puedes registrar progreso para otro usuario.' });
  }
  const targetUser = resolveUsernameKey(db.allProfiles, username) || authUser;
  const safeCount = validatePositiveInt(count ?? 1, 1, 25);
  if (safeCount === null) {
    return res.status(400).json({ error: 'Incremento de progreso inválido.' });
  }

  if (!db.missionProgress) db.missionProgress = {};
  if (!db.missionProgress[targetUser]) db.missionProgress[targetUser] = {};

  const current = db.missionProgress[targetUser][actionType] || 0;
  db.missionProgress[targetUser][actionType] = current + safeCount;

  saveDatabase(db);
  res.json({ success: true, progress: db.missionProgress[targetUser] });
});

// Helper: Calculate current reference period key (consistent timezone UTC)
function getPeriodKey(category: 'daily' | 'weekly' | 'monthly'): string {
  const now = new Date();
  const year = now.getUTCFullYear();
  const month = String(now.getUTCMonth() + 1).padStart(2, '0');
  const day = String(now.getUTCDate()).padStart(2, '0');

  if (category === 'daily') {
    return `${year}-${month}-${day}`;
  } else if (category === 'weekly') {
    // ISO week number
    const target = new Date(now.valueOf());
    const dayNr = (now.getUTCDay() + 6) % 7;
    target.setUTCDate(target.getUTCDate() - dayNr + 3);
    const firstThursday = target.valueOf();
    target.setUTCMonth(0, 1);
    if (target.getUTCDay() !== 4) {
      target.setUTCMonth(0, 1 + ((4 - target.getUTCDay() + 7) % 7));
    }
    const week = 1 + Math.ceil((firstThursday - target.valueOf()) / 604800000);
    return `${year}-W${week}`;
  } else {
    return `${year}-${month}`;
  }
}

// CLAIM MISSION REWARD: Server-authoritative claiming with atomic reward crediting & ledger recording
app.post('/api/missions/:id/claim', requireAuth, (req, res) => {
  const { id } = req.params;
  const authUser = (req as any).user.username;
  const { username } = req.body;
  if (username && username.toLowerCase() !== authUser.toLowerCase()) {
    return res.status(403).json({ error: 'No tienes autorización para reclamar recompensas en otra cuenta.' });
  }

  const effectiveUser = authUser;
  const profile = db.allProfiles[effectiveUser];
  if (!profile) return res.status(404).json({ error: 'Perfil de usuario no encontrado.' });

  const mission = (db.missions || []).find((m: any) => m.id === id);
  if (!mission) return res.status(404).json({ error: 'Misión no encontrada.' });
  if (!mission.isActive) return res.status(400).json({ error: 'Esta misión no está activa actualmente.' });

  const periodKey = getPeriodKey(mission.category);

  // Check if already claimed in this cycle
  if (!Array.isArray(db.missionClaims)) db.missionClaims = [];
  const alreadyClaimed = db.missionClaims.some(
    (c: any) => c.missionId === id && c.username === effectiveUser && c.periodKey === periodKey
  );

  if (alreadyClaimed) {
    return res.status(400).json({
      error: `Ya has reclamado la recompensa de esta misión para el periodo actual (${periodKey}).`
    });
  }

  const progressKey = resolveUsernameKey(db.missionProgress, effectiveUser) || effectiveUser;
  const userProgress = (db.missionProgress && db.missionProgress[progressKey]?.[mission.reqType]) || 0;
  const isPrivileged = isUnlimitedBalanceProfile(profile);

  if (!isPrivileged && userProgress < mission.targetCount) {
    return res.status(400).json({
      error: `Aún no has completado los requisitos de la misión (${userProgress}/${mission.targetCount} ${mission.reqType}).`
    });
  }

  // Atomic Crediting
  const rCoins = Math.max(0, Number(mission.rewardCoins) || 0);
  const rGems = Math.max(0, Number(mission.rewardGems) || 0);

  profile.coins = (profile.coins || 0) + rCoins;
  profile.gems = (profile.gems || 0) + rGems;

  // Record Claim
  const claimRecord = {
    id: 'claim-' + Date.now() + '-' + Math.floor(Math.random() * 1000),
    username: effectiveUser,
    missionId: id,
    missionTitle: mission.title,
    category: mission.category,
    periodKey,
    rewardCoins: rCoins,
    rewardGems: rGems,
    claimedAt: new Date().toISOString()
  };
  db.missionClaims.push(claimRecord);

  // Record into Central Economy Ledger
  if (rCoins > 0) {
    recordLedger({
      username: effectiveUser,
      type: 'earn_coins',
      currency: 'coins',
      amount: rCoins,
      balanceAfter: profile.coins,
      reason: `Misión ${mission.category.toUpperCase()}: ${mission.title}`
    });
  }

  if (rGems > 0) {
    recordLedger({
      username: effectiveUser,
      type: 'earn_gems',
      currency: 'gems',
      amount: rGems,
      balanceAfter: profile.gems,
      reason: `Misión ${mission.category.toUpperCase()}: ${mission.title}`
    });
  }

  saveDatabase(db);

  return res.json({
    success: true,
    claim: claimRecord,
    profile: getSafeProfiles(db, effectiveUser)[effectiveUser] || profile,
    message: `¡Recompensa reclamada con éxito! +${rCoins} Coins y +${rGems} Gems acreditadas.`
  });
});

// GEM TRANSFER BETWEEN USERS: Atomic, strictly server-validated, ledger recorded
app.post('/api/economy/transfer-gems', requireAuth, (req, res) => {
  const authUser = (req as any).user.username;
  const { senderUsername, recipientUsername, amount, message } = req.body;
  const gemAmount = validatePositiveInt(amount, 1, 100_000);

  if (senderUsername && senderUsername.toLowerCase() !== authUser.toLowerCase()) {
    return res.status(403).json({ error: 'No tienes autorización para transferir Gemas desde otra cuenta.' });
  }
  const effectiveSender = resolveUsernameKey(db.allProfiles, authUser) || authUser;

  if (!recipientUsername) {
    return res.status(400).json({ error: 'Remitente y destinatario son requeridos.' });
  }

  if (gemAmount === null) {
    return res.status(400).json({ error: 'La cantidad de Gemas a transferir debe ser un número entero mayor a cero.' });
  }

  if (effectiveSender.trim().toLowerCase() === String(recipientUsername).trim().toLowerCase()) {
    return res.status(400).json({ error: 'No puedes transferir Gemas a tu propia cuenta.' });
  }

  const sender = db.allProfiles[effectiveSender];
  if (!sender) return res.status(404).json({ error: 'Cuenta de remitente no encontrada.' });
  if (sender.isSuspended) {
    return res.status(403).json({ error: 'Tu cuenta se encuentra suspendida y no puede realizar transferencias.' });
  }

  const recipientKey = resolveUsernameKey(db.allProfiles, String(recipientUsername).trim());
  if (!recipientKey) {
    return res.status(404).json({ error: `El destinatario "@${recipientUsername}" no existe en la plataforma.` });
  }
  const recipient = db.allProfiles[recipientKey];

  // Balance Check (Only Admins/Founders have unlimited gems)
  const isSenderPrivileged = isUnlimitedBalanceProfile(sender);
  if (!isSenderPrivileged && (sender.gems || 0) < gemAmount) {
    return res.status(400).json({
      error: `Saldo insuficiente. Tienes ${sender.gems || 0} Gemas e intentas transferir ${gemAmount}.`
    });
  }

  // Atomic Transfer
  if (!isSenderPrivileged) {
    sender.gems -= gemAmount;
  }
  recipient.gems = (recipient.gems || 0) + gemAmount;

  // Track mission progress for gem_transfer
  if (!db.missionProgress) db.missionProgress = {};
  if (!db.missionProgress[effectiveSender]) db.missionProgress[effectiveSender] = {};
  db.missionProgress[effectiveSender]['gem_transfer'] = (db.missionProgress[effectiveSender]['gem_transfer'] || 0) + 1;

  // Create Ledger entries for both sides
  const senderTx = recordLedger({
    username: effectiveSender,
    type: 'transfer_gems_sent',
    currency: 'gems',
    amount: gemAmount,
    balanceAfter: sender.gems,
    reason: `Transferencia enviada a @${recipientKey}: ${message ? `"${String(message).slice(0, 120)}"` : 'Sin mensaje'}`,
    relatedUser: recipientKey
  });

  const recipientTx = recordLedger({
    username: recipientKey,
    type: 'transfer_gems_received',
    currency: 'gems',
    amount: gemAmount,
    balanceAfter: recipient.gems,
    reason: `Transferencia recibida de @${effectiveSender}: ${message ? `"${String(message).slice(0, 120)}"` : 'Sin mensaje'}`,
    relatedUser: effectiveSender
  });

  // Notification for recipient
  if (!Array.isArray(db.notifications)) db.notifications = [];
  db.notifications.unshift({
    id: 'notif-' + Date.now(),
    recipient: recipientKey,
    sender: effectiveSender,
    type: 'gift',
    title: '💎 ¡Has recibido Gemas!',
    message: `@${effectiveSender} te ha transferido ${gemAmount} Gemas Estelares. ${message ? `Mensaje: "${String(message).slice(0, 120)}"` : ''}`,
    date: new Date().toISOString(),
    read: false
  });

  saveDatabase(db);

  return res.json({
    success: true,
    gemAmount,
    senderGems: sender.gems,
    recipientGems: recipient.gems,
    recipientUsername: recipientKey,
    senderTx,
    recipientTx,
    message: `¡Transferencia exitosa de ${gemAmount} Gemas a @${recipientKey}!`
  });
});

// GET USER ECONOMIC HISTORY (LEDGER)
app.get('/api/economy/ledger/:username', requireAuth, (req, res) => {
  const { username } = req.params;
  const authUser = (req as any).user.username;
  const isPrivileged = (req as any).user.isFounder || (req as any).user.accountType === 'admin';
  if (authUser.toLowerCase() !== username.toLowerCase() && !isPrivileged) {
    return res.status(403).json({ error: 'No tienes autorización para consultar el historial financiero de otro usuario.' });
  }
  const userLedger = (db.economyLedger || []).filter(
    (tx: any) => tx?.username && tx.username.toLowerCase() === username.toLowerCase()
  );
  res.json({ success: true, ledger: userLedger });
});

// ==========================================
// STORE PURCHASE WITH SERVER-SIDE ECONOMY VALIDATION
// ==========================================
app.post('/api/store/purchase', requireAuth, (req, res) => {
  const authUser = (req as any).user.username;
  const { username, productId, chosenCurrency, currency, quantity, couponCode } = req.body;
  if (!productId) return res.status(400).json({ error: 'Datos de compra incompletos.' });

  const buyerUsername = resolveUsernameKey(db.allProfiles, authUser) || authUser;
  if (username && username.toLowerCase() !== authUser.toLowerCase()) {
    return res.status(403).json({ error: 'No tienes autorización para realizar compras con la cuenta de otro usuario.' });
  }

  const profile = db.allProfiles[buyerUsername];
  if (!profile) return res.status(404).json({ error: 'Usuario no encontrado.' });
  if (profile.isSuspended) {
    return res.status(403).json({ error: 'Tu cuenta se encuentra suspendida.' });
  }

  const product = (db.products || []).find((p: any) => p.id === productId);
  if (!product) return res.status(404).json({ error: 'Producto no encontrado.' });

  const cleanCouponCode = couponCode ? String(couponCode).trim().toUpperCase() : '';
  const coupon = cleanCouponCode
    ? (db.discountCoupons || []).find((c: any) => c.code === cleanCouponCode)
    : undefined;
  if (cleanCouponCode && !coupon) {
    return res.status(400).json({ error: 'Cupón no válido o inexistente.' });
  }

  const validation = validatePurchaseRequest({
    product,
    quantity: quantity ?? 1,
    currency: chosenCurrency || currency,
    coupon
  });

  if (!validation.ok || !validation.currency || !validation.totalCost || !validation.quantity) {
    return res.status(400).json({ error: validation.error || 'Solicitud de compra inválida.' });
  }

  const chosenCur = validation.currency;
  const totalCost = validation.totalCost;
  const qty = validation.quantity;
  const isPrivileged = isUnlimitedBalanceProfile(profile);

  if (!isPrivileged) {
    const balance = chosenCur === 'gems' ? (profile.gems || 0) : (profile.coins || 0);
    if (balance < totalCost) {
      return res.status(400).json({
        error: `Saldo insuficiente de ${chosenCur === 'gems' ? 'Gemas' : 'Coins'}. Necesitas ${totalCost} y dispones de ${balance}.`
      });
    }

    if (chosenCur === 'gems') {
      profile.gems = Math.max(0, (profile.gems || 0) - totalCost);
    } else {
      profile.coins = Math.max(0, (profile.coins || 0) - totalCost);
    }

    recordLedger({
      username: buyerUsername,
      type: chosenCur === 'gems' ? 'spend_gems' : 'spend_coins',
      currency: chosenCur,
      amount: totalCost,
      balanceAfter: chosenCur === 'gems' ? profile.gems : profile.coins,
      reason: `Compra en Tienda: ${product.name}`
    });
  }

  if (coupon && validation.discountPercent && validation.discountPercent > 0) {
    coupon.usesCount = (coupon.usesCount || 0) + 1;
  }

  // Decrement stock if fixed
  if (product.stockType === 'fixed') {
    product.stockCount = Math.max(0, (Number(product.stockCount) || 0) - qty);
  }

  // If it's a frame, unlock in user's ownedFrames!
  if (product.isFrame) {
    if (!Array.isArray(profile.ownedFrames)) profile.ownedFrames = [];
    if (!profile.ownedFrames.includes(product.id)) {
      profile.ownedFrames.push(product.id);
    }
    profile.selectedFrameId = product.id;
    if (product.frameConfig?.defaultColor) {
      profile.customFrameColor = product.frameConfig.defaultColor;
    }
  }

  // If it's an album, create UserAlbum server-side too
  let createdAlbum: any = null;
  if (product.isAlbum) {
    if (!Array.isArray(db.userAlbums)) db.userAlbums = [];
    createdAlbum = {
      id: 'ualbum-' + Date.now(),
      ownerUsername: buyerUsername,
      productId: product.id,
      albumName: product.name,
      albumType: product.albumType || 'full',
      coverImage: (product.images && product.images[0]) || '',
      associatedArtists: product.associatedArtists || [],
      tracks: product.tracks || [],
      purchasedAt: new Date().toISOString(),
      isPreorder: !!product.isPreorder,
      isOpened: false
    };
    db.userAlbums.unshift(createdAlbum);
  }

  // Add to inventory with ownerUsername
  const newInventoryItem = {
    id: 'inv-' + Date.now() + '-' + Math.floor(Math.random() * 1000),
    ownerUsername: buyerUsername,
    productId: product.id,
    productName: product.name,
    image: (product.images && product.images[0]) || '',
    description: product.description,
    pricePaid: totalCost,
    currencyUsed: chosenCur,
    purchasedAt: new Date().toISOString(),
    category: product.category || 'merch'
  };

  if (!Array.isArray(db.inventory)) db.inventory = [];
  db.inventory.unshift(newInventoryItem);

  if (!Array.isArray(db.productPurchases)) db.productPurchases = [];
  db.productPurchases.unshift({
    id: 'pur-' + Date.now(),
    buyerUsername,
    productId: product.id,
    productName: product.name,
    quantity: qty,
    currencyUsed: chosenCur,
    totalPaid: totalCost,
    purchasedAt: new Date().toISOString()
  });

  // Track mission progress for collect_items
  if (!db.missionProgress) db.missionProgress = {};
  if (!db.missionProgress[buyerUsername]) db.missionProgress[buyerUsername] = {};
  db.missionProgress[buyerUsername]['collect_items'] = (db.missionProgress[buyerUsername]['collect_items'] || 0) + 1;

  saveDatabase(db);

  return res.json({
    success: true,
    profile: getSafeProfiles(db, buyerUsername)[buyerUsername] || profile,
    inventoryItem: newInventoryItem,
    userAlbum: createdAlbum,
    product,
    message: `¡Compra confirmada! Has adquirido "${product.name}".`
  });
});

// User Profile Updates & Persistence (Strict allowlist & case-insensitive lookup)
app.patch('/api/users/:username/profile', requireAuth, (req, res) => {
  const { username } = req.params;
  const actor = (req as any).user;
  const isPrivileged = isAdminOrFounder(actor);

  const canonicalKey = resolveUsernameKey(db.allProfiles, username);
  if (!canonicalKey) {
    return res.status(404).json({ error: 'Usuario no encontrado.' });
  }

  if (actor.username.toLowerCase() !== canonicalKey.toLowerCase() && !isPrivileged) {
    return res.status(403).json({ error: 'No tienes autorización para editar el perfil de otro usuario.' });
  }

  const existing = db.allProfiles[canonicalKey];
  if (existing.isFounder && !actor.isFounder && actor.username.toLowerCase() !== canonicalKey.toLowerCase()) {
    return res.status(403).json({ error: 'Solo el CEO Fundador puede modificar el perfil fundador.' });
  }

  const sanitizedUpdates = sanitizeSelfProfilePatch(existing, req.body || {}, isPrivileged);
  if (Object.keys(sanitizedUpdates).length === 0) {
    return res.json({ success: true, profile: getSafeProfiles(db, actor.username)[canonicalKey] || existing });
  }

  db.allProfiles[canonicalKey] = {
    ...existing,
    ...sanitizedUpdates,
    username: canonicalKey
  };

  if (isPrivileged && actor.username.toLowerCase() !== canonicalKey.toLowerCase()) {
    appendAuditLog(db, {
      adminUsername: actor.username,
      action: 'EDIT_USER_PROFILE',
      targetUser: canonicalKey,
      details: `Actualizó perfil de @${canonicalKey}: ${Object.keys(sanitizedUpdates).join(', ')}`
    });
  }

  saveDatabase(db);
  res.json({ success: true, profile: getSafeProfiles(db, actor.username)[canonicalKey] || db.allProfiles[canonicalKey] });
});

// Products Creation & Deletion Endpoints
app.delete('/api/products/:id', requireAuth, (req, res) => {
  const { id } = req.params;
  const user = (req as any).user;
  if (!Array.isArray(db.products)) db.products = [];
  const target = db.products.find((p: any) => p.id === id);
  if (!target) return res.status(404).json({ error: 'Producto no encontrado.' });

  const canManageStore = hasDelegatedPermission(user, db.adminDelegations, 'canManageStore', db.firstRegisteredUser);
  const isCreator = target.createdBy && target.createdBy.toLowerCase() === user.username.toLowerCase();
  const isReseller = target.resellerUsername && target.resellerUsername.toLowerCase() === user.username.toLowerCase();
  if (!canManageStore && !isCreator && !isReseller) {
    return res.status(403).json({ error: 'No tienes autorización para eliminar este producto.' });
  }

  const initialLen = db.products.length;
  db.products = db.products.filter((p: any) => p.id !== id);
  if (canManageStore && !isCreator) {
    appendAuditLog(db, {
      adminUsername: user.username,
      action: 'DELETE_PRODUCT',
      details: `Eliminó producto "${target.name}" (${id})`
    });
  }
  saveDatabase(db);
  res.json({ success: true, deleted: db.products.length < initialLen, products: db.products });
});

app.post('/api/products', requireAuth, (req, res) => {
  const user = (req as any).user;
  const profile = db.allProfiles[user.username];
  const isStoreAdmin = hasDelegatedPermission(user, db.adminDelegations, 'canManageStore', db.firstRegisteredUser);
  const isAuthorizedSeller =
    isStoreAdmin ||
    user.accountType === 'artista' ||
    user.accountType === 'diseñador' ||
    Boolean(profile?.isVendorApproved);

  if (!isAuthorizedSeller) {
    return res.status(403).json({ error: 'Solo administradores autorizados, artistas, diseñadores o proveedores aprobados pueden publicar productos.' });
  }

  const newProd = { ...req.body };
  if (!newProd || !newProd.name || !String(newProd.name).trim()) {
    return res.status(400).json({ error: 'El nombre del producto es obligatorio.' });
  }
  const stockCountNum = Number(newProd.stockCount);
  if (newProd.stockType === 'fixed' && (isNaN(stockCountNum) || stockCountNum < 0)) {
    return res.status(400).json({ error: 'La cantidad de copias del producto debe ser un número válido.' });
  }

  const priceCoinsNum = Number(newProd.priceCoins ?? 0);
  const priceGemsNum = Number(newProd.priceGems ?? 0);
  if (!Number.isFinite(priceCoinsNum) || priceCoinsNum < 0 || !Number.isFinite(priceGemsNum) || priceGemsNum < 0) {
    return res.status(400).json({ error: 'Los precios del producto deben ser valores positivos.' });
  }
  if ((newProd.currencyType || 'coins') === 'coins' && priceCoinsNum <= 0) {
    return res.status(400).json({ error: 'El precio en Coins debe ser mayor a 0.' });
  }
  if (newProd.currencyType === 'gems' && priceGemsNum <= 0) {
    return res.status(400).json({ error: 'El precio en Gemas debe ser mayor a 0.' });
  }
  if (newProd.currencyType === 'both' && (priceCoinsNum <= 0 || priceGemsNum <= 0)) {
    return res.status(400).json({ error: 'Productos con moneda mixta deben tener precio válido en Coins y Gemas.' });
  }

  if (!newProd.id) {
    newProd.id = 'prod-' + Date.now() + '-' + Math.floor(Math.random() * 1000);
  }
  newProd.name = String(newProd.name).trim();
  newProd.createdBy = user.username;
  newProd.priceCoins = Math.round(priceCoinsNum);
  newProd.priceGems = Math.round(priceGemsNum);
  newProd.stockCount = isNaN(stockCountNum) ? 10 : Math.floor(stockCountNum);

  if (!Array.isArray(db.products)) db.products = [];
  const existingIdx = db.products.findIndex((p: any) => p.id === newProd.id);
  if (existingIdx !== -1) {
    const existingProd = db.products[existingIdx];
    const isOwner = existingProd.createdBy?.toLowerCase() === user.username.toLowerCase();
    if (!isOwner && !isStoreAdmin) {
      return res.status(403).json({ error: 'No puedes editar un producto que pertenece a otro vendedor.' });
    }
    db.products[existingIdx] = { ...existingProd, ...newProd, createdBy: existingProd.createdBy };
  } else {
    db.products.unshift(newProd);
  }
  saveDatabase(db);
  res.json({ success: true, product: newProd, products: db.products });
});

// Survival Management Endpoints
app.post('/api/survivals', requireAuth, requireRole(['admin']), requireDelegation('canManageSurvival'), (req, res) => {
  const adminUser = (req as any).user.username;
  const newShow = req.body;
  if (!Array.isArray(db.survivals)) db.survivals = [];
  if (newShow && newShow.id) {
    db.survivals.unshift({ ...newShow, createdBy: newShow.createdBy || adminUser });
    appendAuditLog(db, {
      adminUsername: adminUser,
      action: 'CREATE_SURVIVAL',
      details: `Creó survival "${newShow.title || newShow.id}"`
    });
    saveDatabase(db);
  }
  res.json({ success: true, survivals: db.survivals });
});

app.delete('/api/survivals/:id', requireAuth, requireRole(['admin']), requireDelegation('canManageSurvival'), (req, res) => {
  const adminUser = (req as any).user.username;
  const { id } = req.params;
  if (!Array.isArray(db.survivals)) db.survivals = [];
  const target = db.survivals.find((s: any) => s.id === id);
  db.survivals = db.survivals.filter((s: any) => s.id !== id);
  if (target) {
    appendAuditLog(db, {
      adminUsername: adminUser,
      action: 'DELETE_SURVIVAL',
      details: `Eliminó survival "${target.title || id}"`
    });
  }
  saveDatabase(db);
  res.json({ success: true, survivals: db.survivals });
});

app.patch('/api/survivals/:id', requireAuth, requireRole(['admin']), requireDelegation('canManageSurvival'), (req, res) => {
  const adminUser = (req as any).user.username;
  const { id } = req.params;
  const updates = req.body;
  if (!Array.isArray(db.survivals)) db.survivals = [];
  db.survivals = db.survivals.map((s: any) => (s.id === id ? { ...s, ...updates } : s));
  appendAuditLog(db, {
    adminUsername: adminUser,
    action: 'UPDATE_SURVIVAL',
    details: `Actualizó survival ${id}`
  });
  saveDatabase(db);
  res.json({ success: true, survivals: db.survivals });
});

app.post('/api/survivals/:id/comments', requireAuth, (req, res) => {
  const { id } = req.params;
  const authUser = (req as any).user.username;
  const { author, text } = req.body;
  if (!text || !String(text).trim()) return res.status(400).json({ error: 'Comentario incompleto.' });
  if (author && author.toLowerCase() !== authUser.toLowerCase()) {
    return res.status(403).json({ error: 'No puedes comentar con otra identidad.' });
  }
  if (!Array.isArray(db.survivals)) db.survivals = [];
  const show = db.survivals.find((s: any) => s.id === id);
  if (!show) return res.status(404).json({ error: 'Survival no encontrado.' });
  if (!Array.isArray(show.comments)) show.comments = [];
  const newComment = { id: 'com-' + Date.now(), author: authUser, text: String(text).trim(), date: new Date().toISOString() };
  show.comments.push(newComment);
  saveDatabase(db);
  res.json({ success: true, comment: newComment });
});

app.post('/api/survivals/:id/favorites', requireAuth, (req, res) => {
  const { id } = req.params;
  const authUser = (req as any).user.username;
  const { fanUsername, contestantUsername } = req.body;
  if (!contestantUsername) return res.status(400).json({ error: 'Datos incompletos.' });
  if (fanUsername && fanUsername.toLowerCase() !== authUser.toLowerCase()) {
    return res.status(403).json({ error: 'No puedes votar favoritos en nombre de otro usuario.' });
  }
  const effectiveFan = authUser;
  if (!Array.isArray(db.survivals)) db.survivals = [];
  const show = db.survivals.find((s: any) => s.id === id);
  if (!show) return res.status(404).json({ error: 'Survival no encontrado.' });
  if (!show.fanFavorites) show.fanFavorites = {};
  const currentFavs: string[] = show.fanFavorites[effectiveFan] || [];
  if (currentFavs.includes(contestantUsername)) {
    show.fanFavorites[effectiveFan] = currentFavs.filter((u: string) => u !== contestantUsername);
  } else {
    if (currentFavs.length >= 3) {
      return res.status(400).json({ error: 'Solo puedes escoger hasta 3 favoritos para apoyar.' });
    }
    show.fanFavorites[effectiveFan] = [...currentFavs, contestantUsername];
  }
  saveDatabase(db);
  res.json({ success: true, favorites: show.fanFavorites[effectiveFan] });
});

// ==========================================
// 2. COLLECTION & WISHLIST (LISTA DE DESEOS)
// ==========================================

// Wishlist Endpoints
app.get('/api/wishlist', (req, res) => {
  const username = String(req.query.username || '').trim();
  if (!username) return res.json({ success: true, wishlist: [] });
  const key = Object.keys(db.wishlists || {}).find((k) => k.toLowerCase() === username.toLowerCase());
  const list = (key && db.wishlists?.[key]) || [];
  res.json({ success: true, wishlist: list });
});

app.get('/api/wishlist/:username', (req, res) => {
  const { username } = req.params;
  const key = Object.keys(db.wishlists || {}).find((k) => k.toLowerCase() === username.toLowerCase());
  const list = (key && db.wishlists?.[key]) || [];
  res.json({ success: true, wishlist: list });
});

app.post('/api/wishlist', requireAuth, (req, res) => {
  const authUser = (req as any).user.username;
  const { username, productId, notes } = req.body;
  if (!productId) return res.status(400).json({ error: 'Datos incompletos.' });
  if (username && username.toLowerCase() !== authUser.toLowerCase()) {
    return res.status(403).json({ error: 'No puedes modificar la lista de deseos de otro usuario.' });
  }
  const effectiveUser = authUser;

  const product = (db.products || []).find((p: any) => p.id === productId);
  if (!product) return res.status(404).json({ error: 'Producto no encontrado.' });

  if (!db.wishlists) db.wishlists = {};
  if (!Array.isArray(db.wishlists[effectiveUser])) db.wishlists[effectiveUser] = [];

  const exists = db.wishlists[effectiveUser].some((w: any) => w.productId === productId);
  if (exists) {
    return res.status(400).json({ error: 'Este artículo ya se encuentra en tu lista de deseos.' });
  }

  const wishItem = {
    id: 'wish-' + Date.now(),
    productId: product.id,
    username: effectiveUser,
    productName: product.name,
    image: (product.images && product.images[0]) || '',
    priceCoins: product.priceCoins,
    priceGems: product.priceGems,
    currencyType: product.currencyType || 'coins',
    isSoldOut: product.stockType === 'fixed' && product.stockCount <= 0,
    notes: notes || '',
    createdAt: new Date().toISOString()
  };

  db.wishlists[effectiveUser].push(wishItem);
  saveDatabase(db);
  res.json({ success: true, wishItem, wishlist: db.wishlists[effectiveUser] });
});

app.delete('/api/wishlist/:username/:wishId', requireAuth, (req, res) => {
  const { username, wishId } = req.params;
  const authUser = (req as any).user.username;
  const isPrivileged = (req as any).user.isFounder || (req as any).user.accountType === 'admin';
  if (authUser.toLowerCase() !== username.toLowerCase() && !isPrivileged) {
    return res.status(403).json({ error: 'No puedes eliminar artículos de la lista de deseos de otro usuario.' });
  }
  const key = Object.keys(db.wishlists || {}).find((k) => k.toLowerCase() === username.toLowerCase()) || username;
  if (db.wishlists && Array.isArray(db.wishlists[key])) {
    db.wishlists[key] = db.wishlists[key].filter((w: any) => w.id !== wishId);
    saveDatabase(db);
  }
  res.json({ success: true, wishlist: (db.wishlists && db.wishlists[key]) || [] });
});

// Gift Wishlisted Item to another user
app.post('/api/wishlist/gift', requireAuth, (req, res) => {
  const authUser = (req as any).user.username;
  const { giverUsername, recipientUsername, wishId } = req.body;
  if (!recipientUsername || !wishId) {
    return res.status(400).json({ error: 'Datos de obsequio incompletos.' });
  }
  if (giverUsername && giverUsername.toLowerCase() !== authUser.toLowerCase()) {
    return res.status(403).json({ error: 'No tienes autorización para regalar en nombre de otra cuenta.' });
  }
  const effectiveGiver = authUser;

  const giver = db.allProfiles[effectiveGiver];
  const recipientKey = Object.keys(db.allProfiles).find((k) => k.toLowerCase() === recipientUsername.toLowerCase());
  const recipient = recipientKey ? db.allProfiles[recipientKey] : null;
  if (!giver || !recipient || !recipientKey) return res.status(404).json({ error: 'Perfiles no encontrados.' });

  const wishList = (db.wishlists && db.wishlists[recipientKey]) || [];
  const wishItem = wishList.find((w: any) => w.id === wishId);
  if (!wishItem) return res.status(404).json({ error: 'Artículo deseado no encontrado en la lista del destinatario.' });

  const product = (db.products || []).find((p: any) => p.id === wishItem.productId);
  if (!product) return res.status(404).json({ error: 'Producto original no encontrado.' });
  if (product.stockType === 'fixed' && product.stockCount <= 0) {
    return res.status(400).json({ error: 'Este artículo está agotado actualmente.' });
  }

  // Check giver funds
  const isPrivileged = giver.accountType === 'admin' || !!giver.isFounder;
  if (!isPrivileged) {
    if (product.currencyType === 'gems') {
      const g = product.priceGems || 0;
      if ((giver.gems || 0) < g) return res.status(400).json({ error: 'Saldo insuficiente de Gemas para regalar este artículo.' });
      giver.gems -= g;
      recordLedger({
        username: effectiveGiver,
        type: 'spend_gems',
        currency: 'gems',
        amount: g,
        balanceAfter: giver.gems,
        reason: `Obsequio de Lista de Deseos para @${recipientKey}: ${product.name}`,
        relatedUser: recipientKey
      });
    } else {
      if ((giver.coins || 0) < product.priceCoins) return res.status(400).json({ error: 'Saldo insuficiente de Coins para regalar este artículo.' });
      giver.coins -= product.priceCoins;
      recordLedger({
        username: effectiveGiver,
        type: 'spend_coins',
        currency: 'coins',
        amount: product.priceCoins,
        balanceAfter: giver.coins,
        reason: `Obsequio de Lista de Deseos para @${recipientKey}: ${product.name}`,
        relatedUser: recipientKey
      });
    }
  }

  if (product.stockType === 'fixed' && product.stockCount > 0) {
    product.stockCount -= 1;
  }

  // Give item to recipient inventory
  if (!Array.isArray(db.inventory)) db.inventory = [];
  const giftInventoryItem = {
    id: 'inv-' + Date.now(),
    ownerUsername: recipientKey,
    productId: product.id,
    productName: product.name,
    image: (product.images && product.images[0]) || '',
    description: `Obsequio especial recibido de @${effectiveGiver}`,
    pricePaid: 0,
    purchasedAt: new Date().toISOString(),
    category: product.category || 'merch'
  };
  db.inventory.push(giftInventoryItem);

  // Remove from recipient's wishlist
  db.wishlists[recipientKey] = wishList.filter((w: any) => w.id !== wishId);

  // Send notification
  if (!Array.isArray(db.notifications)) db.notifications = [];
  db.notifications.unshift({
    id: 'notif-' + Date.now(),
    recipient: recipientKey,
    sender: effectiveGiver,
    type: 'gift',
    title: '🎁 ¡Te han regalado un artículo deseado!',
    message: `@${effectiveGiver} ha hecho realidad tu deseo y te ha obsequiado "${product.name}". Ya está en tu inventario.`,
    date: new Date().toISOString(),
    read: false
  });

  saveDatabase(db);
  res.json({ success: true, message: `¡Has obsequiado "${product.name}" a @${recipientKey} exitosamente!` });
});

// Showcase Vitrina Personal Management
app.get('/api/showcase/:username', (req, res) => {
  const { username } = req.params;
  const items = (db.showcaseCollections && db.showcaseCollections[username]) || [];
  res.json({ success: true, items });
});

app.post('/api/showcase/save', requireAuth, (req, res) => {
  const authUser = (req as any).user.username;
  const { username, showcaseItems } = req.body;
  if (!Array.isArray(showcaseItems)) {
    return res.status(400).json({ error: 'Datos de vitrina inválidos.' });
  }
  if (username && username.toLowerCase() !== authUser.toLowerCase() && (req as any).user.accountType !== 'admin' && !(req as any).user.isFounder) {
    return res.status(403).json({ error: 'No tienes autorización para modificar la vitrina de otro usuario.' });
  }
  const targetUser = username || authUser;

  if (!db.showcaseCollections) db.showcaseCollections = {};
  db.showcaseCollections[targetUser] = showcaseItems;

  if (db.allProfiles[targetUser]) {
    db.allProfiles[targetUser].showcaseItemIds = showcaseItems.map((i: any) => i.id);
  }

  saveDatabase(db);
  res.json({ success: true, showcaseItems: db.showcaseCollections[targetUser] });
});

// ==========================================
// 3. PROFILE CUSTOMIZATION — FRAMES & TRANSPARENT FRAMES
// ==========================================
app.put('/api/user/customization', requireAuth, (req, res) => {
  const authUser = (req as any).user.username;
  const isAdmin = (req as any).user.accountType === 'admin' || !!(req as any).user.isFounder;
  const {
    username,
    ringColor,
    customFrameColor,
    transparentFrame,
    customTransparentFrame,
    frameScale,
    frameOffsetX,
    frameOffsetY,
    selectedFrameId,
    fandomDisplayMode,
    displayedFandomTags,
    notificationPreferences,
    displayedBadges,
    mutedConversations
  } = req.body;

  if (username && username.toLowerCase() !== authUser.toLowerCase() && !isAdmin) {
    return res.status(403).json({ error: 'No tienes autorización para personalizar otro perfil.' });
  }
  const targetUser = resolveUsernameKey(db.allProfiles, username || authUser);
  const profile = targetUser ? db.allProfiles[targetUser] : null;
  if (!profile || !targetUser) return res.status(404).json({ error: 'Perfil no encontrado.' });

  // Update ring color / frame color
  if (ringColor) profile.ringColor = ringColor;
  if (customFrameColor) profile.customFrameColor = customFrameColor;
  if (selectedFrameId !== undefined) {
    if (selectedFrameId === null || selectedFrameId === '') {
      profile.selectedFrameId = null;
    } else if (isAdmin || (Array.isArray(profile.ownedFrames) && profile.ownedFrames.includes(selectedFrameId))) {
      profile.selectedFrameId = selectedFrameId;
    } else {
      return res.status(403).json({ error: 'No posees este marco en tu colección.' });
    }
  }

  // Transparent frames: Server-side check for privilege (Artists, CEOs, Premium fans)
  const isPrivileged = profile.accountType === 'artista' || profile.accountType === 'admin' || !!profile.isFounder || profile.accountType === 'premium_fan';

  if (customTransparentFrame !== undefined) {
    if (customTransparentFrame && !isPrivileged) {
      return res.status(403).json({
        error: 'Los marcos transparentes personalizados están reservados para Artistas Oficiales, CEOs y Usuarios Premium.'
      });
    }
    profile.customTransparentFrame = customTransparentFrame;
    profile.transparentFrame = customTransparentFrame;
  } else if (transparentFrame !== undefined) {
    profile.transparentFrame = transparentFrame;
  }

  if (frameScale !== undefined && Number.isFinite(Number(frameScale))) {
    profile.frameScale = Math.min(2.5, Math.max(0.5, Number(frameScale)));
  }
  if (frameOffsetX !== undefined && Number.isFinite(Number(frameOffsetX))) {
    profile.frameOffsetX = Math.min(100, Math.max(-100, Number(frameOffsetX)));
  }
  if (frameOffsetY !== undefined && Number.isFinite(Number(frameOffsetY))) {
    profile.frameOffsetY = Math.min(100, Math.max(-100, Number(frameOffsetY)));
  }

  // Fandom tags & preference configuration
  if (fandomDisplayMode) profile.fandomDisplayMode = fandomDisplayMode;
  if (Array.isArray(displayedFandomTags)) profile.displayedFandomTags = displayedFandomTags.slice(0, 10);
  if (notificationPreferences && typeof notificationPreferences === 'object') {
    profile.notificationPreferences = { ...(profile.notificationPreferences || {}), ...notificationPreferences };
  }
  if (Array.isArray(displayedBadges)) {
    const ownedBadgeIds = new Set((profile.customBadges || []).map((b: any) => b.id));
    profile.displayedBadges = isAdmin
      ? displayedBadges.slice(0, 5)
      : displayedBadges.filter((id: string) => ownedBadgeIds.has(id)).slice(0, 5);
  }
  if (Array.isArray(mutedConversations)) profile.mutedConversations = mutedConversations;

  // Track mission progress for customize_profile
  if (!db.missionProgress) db.missionProgress = {};
  if (!db.missionProgress[targetUser]) db.missionProgress[targetUser] = {};
  db.missionProgress[targetUser]['customize_profile'] = (db.missionProgress[targetUser]['customize_profile'] || 0) + 1;

  saveDatabase(db);
  res.json({ success: true, profile: getSafeProfiles(db, targetUser)[targetUser] || profile });
});

// ==========================================
// 7. SECURITY AUDITING, REPORTING & BLOCKING
// ==========================================
app.post('/api/security/report', requireAuth, (req, res) => {
  const authUser = (req as any).user.username;
  const {
    reporterUsername,
    reportedUsername,
    reportedTargetUsername,
    reportedItemType,
    reportedItemId,
    reportedItemTitle,
    motive,
    description,
    reason,
    category,
    proofUrl,
    screenshotUrl,
    evidenceUrls
  } = req.body;

  if (reporterUsername && reporterUsername.toLowerCase() !== authUser.toLowerCase()) {
    return res.status(403).json({ error: 'No puedes enviar reportes suplantando a otro usuario.' });
  }

  const finalTarget = String(reportedTargetUsername || reportedUsername || '').trim();
  const finalReason = String(reason || description || motive || '').trim();
  const finalCategory = String(motive || category || 'conducta_inapropiada').trim();

  if (!finalTarget || !finalReason) {
    return res.status(400).json({ error: 'Datos del reporte incompletos.' });
  }

  const newReport = {
    id: 'rep-' + Date.now(),
    reporterUsername: authUser,
    reportedUsername: finalTarget,
    reportedTargetUsername: finalTarget,
    reportedItemType: reportedItemType || 'usuario',
    reportedItemId: reportedItemId || undefined,
    reportedItemTitle: reportedItemTitle || undefined,
    motive: finalCategory,
    reason: finalReason,
    description: String(description || finalReason).trim(),
    category: finalCategory,
    proofUrl: proofUrl || screenshotUrl || '',
    screenshotUrl: screenshotUrl || proofUrl || '',
    evidenceUrls: Array.isArray(evidenceUrls) ? evidenceUrls : (screenshotUrl ? [screenshotUrl] : []),
    status: 'pending',
    createdAt: new Date().toISOString()
  };

  if (!Array.isArray(db.userReports)) db.userReports = [];
  db.userReports.unshift(newReport);

  // Notify Founders
  if (!Array.isArray(db.notifications)) db.notifications = [];
  db.notifications.unshift({
    id: 'notif-' + Date.now(),
    recipient: db.firstRegisteredUser || 'admin',
    type: 'system',
    title: '🛡️ Nuevo Reporte de Seguridad de Usuario',
    message: `@${authUser} reportó a @${finalTarget}. Motivo: ${finalReason.slice(0, 80)}`,
    date: new Date().toISOString(),
    read: false
  });

  saveDatabase(db);
  res.json({ success: true, report: newReport, message: 'Reporte enviado a la administración para revisión.' });
});

app.post('/api/security/block', requireAuth, (req, res) => {
  const authUser = (req as any).user.username;
  const { username, targetUsername, action } = req.body;
  if (!targetUsername) return res.status(400).json({ error: 'Datos incompletos.' });
  if (username && username.toLowerCase() !== authUser.toLowerCase()) {
    return res.status(403).json({ error: 'No tienes autorización para modificar bloqueos de otro usuario.' });
  }
  const effectiveUser = authUser;

  if (!db.blockedUsers) db.blockedUsers = {};
  if (!Array.isArray(db.blockedUsers[effectiveUser])) db.blockedUsers[effectiveUser] = [];

  if (action === 'unblock') {
    db.blockedUsers[effectiveUser] = db.blockedUsers[effectiveUser].filter((u: string) => u !== targetUsername);
  } else {
    if (!db.blockedUsers[effectiveUser].includes(targetUsername)) {
      db.blockedUsers[effectiveUser].push(targetUsername);
    }
  }

  saveDatabase(db);
  res.json({ success: true, blockedUsers: db.blockedUsers[effectiveUser] });
});

app.get('/api/admin/audit-log', requireAuth, requireRole(['admin']), (req, res) => {
  res.json({ success: true, auditLog: db.adminAuditLog || [] });
});

// 0. ADMIN USER MANAGEMENT (Server-authoritative role, coins/gems, suspension edits)
const VALID_ACCOUNT_TYPES = ['fan', 'premium_fan', 'trainee', 'artista', 'diseñador', 'moderador', 'admin'];
app.patch('/api/admin/users/:username', requireAuth, requireRole(['admin']), (req, res) => {
  const actor = (req as any).user;
  const targetKey = resolveUsernameKey(db.allProfiles, req.params.username);
  if (!targetKey) return res.status(404).json({ error: 'Usuario no encontrado.' });
  const target = db.allProfiles[targetKey];

  if (target.isFounder && !actor.isFounder) {
    return res.status(403).json({ error: 'Solo el CEO Fundador puede modificar los permisos o saldo de la cuenta fundadora.' });
  }

  const { accountType, coins, gems, isSuspended, suspensionReason } = req.body || {};
  const changes: string[] = [];

  if (accountType !== undefined) {
    if (!VALID_ACCOUNT_TYPES.includes(accountType)) {
      return res.status(400).json({ error: 'Tipo de cuenta inválido.' });
    }
    if (accountType === 'admin' && !actor.isFounder && actor.username.toLowerCase() !== (db.firstRegisteredUser || '').toLowerCase()) {
      return res.status(403).json({ error: 'Solo el CEO Fundador puede asignar el rango Administrador.' });
    }
    if (target.isFounder && accountType !== 'admin') {
      return res.status(400).json({ error: 'No se puede degradar el rol de la cuenta fundadora.' });
    }
    target.accountType = accountType;
    changes.push(`rol=${accountType}`);
  }

  if (coins !== undefined) {
    const numCoins = Number(coins);
    if (!Number.isFinite(numCoins) || numCoins < 0) {
      return res.status(400).json({ error: 'Cantidad de Coins inválida.' });
    }
    const prevCoins = Number(target.coins) || 0;
    target.coins = Math.floor(numCoins);
    const diff = target.coins - prevCoins;
    if (diff !== 0) {
      recordLedger({
        username: targetKey,
        type: diff > 0 ? 'earn_coins' : 'spend_coins',
        currency: 'coins',
        amount: Math.abs(diff),
        balanceAfter: target.coins,
        reason: `Ajuste administrativo por @${actor.username}`
      });
    }
    changes.push(`coins=${target.coins}`);
  }

  if (gems !== undefined) {
    const numGems = Number(gems);
    if (!Number.isFinite(numGems) || numGems < 0) {
      return res.status(400).json({ error: 'Cantidad de Gemas inválida.' });
    }
    const prevGems = Number(target.gems) || 0;
    target.gems = Math.floor(numGems);
    const diff = target.gems - prevGems;
    if (diff !== 0) {
      recordLedger({
        username: targetKey,
        type: diff > 0 ? 'earn_gems' : 'spend_gems',
        currency: 'gems',
        amount: Math.abs(diff),
        balanceAfter: target.gems,
        reason: `Ajuste administrativo por @${actor.username}`
      });
    }
    changes.push(`gems=${target.gems}`);
  }

  if (isSuspended !== undefined) {
    if (target.isFounder && isSuspended) {
      return res.status(403).json({ error: 'No se puede suspender la cuenta fundadora.' });
    }
    target.isSuspended = Boolean(isSuspended);
    if (target.isSuspended) {
      target.suspensionReason = String(suspensionReason || 'Suspensión administrativa');
      revokeUserSessions(db.activeSessions, targetKey);
    } else {
      delete target.suspensionReason;
      delete target.suspensionExpires;
    }
    changes.push(`suspended=${target.isSuspended}`);
  }

  if (changes.length > 0) {
    appendAuditLog(db, {
      adminUsername: actor.username,
      action: 'ADMIN_UPDATE_USER',
      targetUser: targetKey,
      details: `Actualizó a @${targetKey}: ${changes.join(', ')}`
    });
    saveDatabase(db);
  }

  res.json({
    success: true,
    profile: getSafeProfiles(db, actor.username)[targetKey] || target,
    allProfiles: getSafeProfiles(db, actor.username)
  });
});

// 1. CEO REQUESTS
app.get('/api/ceo-requests', requireAuth, (req, res) => {
  const user = (req as any).user;
  if (user.isFounder || user.accountType === 'admin') {
    return res.json(db.ceoRequests || []);
  }
  const userRequests = (db.ceoRequests || []).filter((r: any) => r.username?.toLowerCase() === user.username.toLowerCase());
  res.json(userRequests);
});

app.post('/api/ceo-requests', requireAuth, (req, res) => {
  const { requestedRole, reason } = req.body;
  const user = (req as any).user;
  const allowedReqRoles = ['admin', 'artista', 'diseñador'];
  const role = allowedReqRoles.includes(requestedRole) ? requestedRole : 'admin';
  const newReq = {
    id: 'ceo-req-' + Date.now() + '-' + Math.floor(Math.random() * 1000),
    username: user.username,
    requestedRole: role,
    reason: String(reason || '').trim(),
    status: 'pending',
    createdAt: new Date().toISOString()
  };
  if (!Array.isArray(db.ceoRequests)) db.ceoRequests = [];
  db.ceoRequests.unshift(newReq);
  saveDatabase(db);
  res.json({ success: true, request: newReq });
});

app.put('/api/ceo-requests/:requestId', requireAuth, requireRole(['admin']), (req, res) => {
  const { requestId } = req.params;
  const { action } = req.body;
  const reviewer = (req as any).user;

  if (!reviewer.isFounder && reviewer.username.toLowerCase() !== (db.firstRegisteredUser || '').toLowerCase()) {
    return res.status(403).json({ error: 'Solo el CEO Fundador puede aprobar o rechazar solicitudes de CEO.' });
  }

  const reqItem = (db.ceoRequests || []).find((r: any) => r.id === requestId);
  if (!reqItem) return res.status(404).json({ error: 'Solicitud no encontrada.' });

  reqItem.status = action === 'approve' ? 'approved' : 'rejected';
  reqItem.reviewedBy = reviewer.username;
  reqItem.reviewedAt = new Date().toISOString();

  const targetKey = resolveUsernameKey(db.allProfiles, reqItem.username);
  if (action === 'approve' && targetKey && db.allProfiles[targetKey]) {
    const promotedRole = reqItem.requestedRole === 'admin' || !reqItem.requestedRole ? 'admin' : reqItem.requestedRole;
    db.allProfiles[targetKey].accountType = promotedRole;
  }

  appendAuditLog(db, {
    adminUsername: reviewer.username,
    action: action === 'approve' ? 'APPROVE_CEO_REQUEST' : 'REJECT_CEO_REQUEST',
    targetUser: targetKey || reqItem.username,
    details: `${action === 'approve' ? 'Aprobó' : 'Rechazó'} solicitud (${reqItem.requestedRole || 'admin'}) de @${reqItem.username}`
  });

  if (!Array.isArray(db.notifications)) db.notifications = [];
  db.notifications.unshift({
    id: 'notif-' + Date.now(),
    recipient: targetKey || reqItem.username,
    sender: reviewer.username,
    type: 'system',
    title: action === 'approve' ? '👑 ¡Solicitud Aprobada!' : 'Solicitud Revisada',
    message: action === 'approve'
      ? `¡Felicidades! Tu solicitud ha sido aprobada por @${reviewer.username}.`
      : `Tu postulación ha sido revisada por @${reviewer.username} y rechazada en esta ocasión.`,
    date: new Date().toISOString(),
    read: false
  });

  saveDatabase(db);
  res.json({ success: true, request: reqItem, allProfiles: getSafeProfiles(db, reviewer.username) });
});

// 2. ADMIN ROLE REQUESTS
app.get('/api/admin/requests', requireAuth, (req, res) => {
  const user = (req as any).user;
  if (user.isFounder || user.accountType === 'admin') {
    return res.json(db.userRequests || []);
  }
  const mine = (db.userRequests || []).filter((r: any) => r.username?.toLowerCase() === user.username.toLowerCase());
  res.json(mine);
});

app.post('/api/admin/requests', requireAuth, (req, res) => {
  const { requestedRole, reason } = req.body;
  const user = (req as any).user;
  const allowedReqRoles = ['trainee', 'artista', 'diseñador', 'moderador'];
  const cleanRole = allowedReqRoles.includes(requestedRole) ? requestedRole : 'trainee';
  const newReq = {
    id: 'req-' + Date.now() + '-' + Math.floor(Math.random() * 1000),
    username: user.username,
    requestedRole: cleanRole,
    reason: String(reason || '').trim(),
    status: 'pending',
    createdAt: new Date().toISOString()
  };
  if (!Array.isArray(db.userRequests)) db.userRequests = [];
  db.userRequests.unshift(newReq);
  saveDatabase(db);
  res.json({ success: true, request: newReq });
});

app.put('/api/admin/requests/:requestId', requireAuth, requireRole(['admin']), (req, res) => {
  const { requestId } = req.params;
  const { action } = req.body;
  const reviewer = (req as any).user;

  const reqItem = (db.userRequests || []).find((r: any) => r.id === requestId);
  if (!reqItem) return res.status(404).json({ error: 'Solicitud no encontrada.' });

  if (reqItem.requestedRole === 'artista' && !hasDelegatedPermission(reviewer, db.adminDelegations, 'canApproveArtist', db.firstRegisteredUser)) {
    return res.status(403).json({ error: 'No tienes permiso delegado para aprobar cuentas de Artista.' });
  }
  if (reqItem.requestedRole === 'trainee' && !hasDelegatedPermission(reviewer, db.adminDelegations, 'canApproveTrainee', db.firstRegisteredUser)) {
    return res.status(403).json({ error: 'No tienes permiso delegado para aprobar cuentas de Trainee.' });
  }
  if (reqItem.requestedRole === 'admin' && !reviewer.isFounder) {
    return res.status(403).json({ error: 'Solo el CEO Fundador puede aprobar solicitudes de Administrador.' });
  }

  reqItem.status = action === 'approve' ? 'approved' : 'rejected';
  reqItem.reviewedBy = reviewer.username;
  reqItem.reviewedAt = new Date().toISOString();

  const targetKey = resolveUsernameKey(db.allProfiles, reqItem.username);
  if (action === 'approve' && targetKey && db.allProfiles[targetKey]) {
    if (VALID_ACCOUNT_TYPES.includes(reqItem.requestedRole)) {
      db.allProfiles[targetKey].accountType = reqItem.requestedRole;
    }
  }

  appendAuditLog(db, {
    adminUsername: reviewer.username,
    action: action === 'approve' ? 'APPROVE_ROLE_REQUEST' : 'REJECT_ROLE_REQUEST',
    targetUser: targetKey || reqItem.username,
    details: `${action === 'approve' ? 'Aprobó' : 'Rechazó'} solicitud de rol "${reqItem.requestedRole}" para @${reqItem.username}`
  });

  if (!Array.isArray(db.notifications)) db.notifications = [];
  db.notifications.unshift({
    id: 'notif-' + Date.now(),
    recipient: targetKey || reqItem.username,
    sender: reviewer.username,
    type: 'system',
    title: action === 'approve' ? `🎉 Rol "${reqItem.requestedRole}" aprobado` : 'Solicitud de rol revisada',
    message: action === 'approve'
      ? `Tu solicitud para cambiar a "${reqItem.requestedRole}" fue aprobada por @${reviewer.username}.`
      : `Tu solicitud para cambiar a "${reqItem.requestedRole}" fue rechazada por @${reviewer.username}.`,
    date: new Date().toISOString(),
    read: false
  });

  saveDatabase(db);
  res.json({ success: true, request: reqItem, allProfiles: getSafeProfiles(db, reviewer.username) });
});

// 3. ADMIN DELEGATIONS
app.get('/api/admin/delegations', requireAuth, (req, res) => {
  const user = (req as any).user;
  if (!user.isFounder && user.accountType !== 'admin') {
    return res.status(403).json({ error: 'Acceso restringido a administradores.' });
  }
  res.json(db.adminDelegations || {});
});

app.post('/api/admin/delegations', requireAuth, requireRole(['admin']), (req, res) => {
  const { targetAdminUsername, permissions } = req.body;
  const user = (req as any).user;
  if (!user.isFounder && user.username.toLowerCase() !== (db.firstRegisteredUser || '').toLowerCase()) {
    return res.status(403).json({ error: 'Solo el CEO Fundador puede delegar permisos administrativos.' });
  }
  if (!targetAdminUsername || !permissions) {
    return res.status(400).json({ error: 'Parámetros de delegación incompletos.' });
  }
  const targetKey = resolveUsernameKey(db.allProfiles, targetAdminUsername) || targetAdminUsername;
  if (!db.adminDelegations) db.adminDelegations = {};
  db.adminDelegations[targetKey] = permissions;

  appendAuditLog(db, {
    adminUsername: user.username,
    action: 'DELEGATE_PERMISSIONS',
    targetUser: targetKey,
    details: `Permisos administrativos delegados a @${targetKey}`
  });

  saveDatabase(db);
  res.json({ success: true, delegations: db.adminDelegations });
});

// AWARDS DIGITAL REWARDS GRANTING
app.post('/api/awards/grant-rewards', requireAuth, requireRole(['admin']), (req, res) => {
  const adminUser = (req as any).user.username;
  const { awardId, categoryId, winnerUsername, trophyName, recognitionTitle } = req.body;
  if (!winnerUsername || !trophyName) return res.status(400).json({ error: 'Datos incompletos.' });

  const winnerKey = resolveUsernameKey(db.allProfiles, winnerUsername);
  const profile = winnerKey ? db.allProfiles[winnerKey] : null;
  if (!profile || !winnerKey) return res.status(404).json({ error: 'Perfil del ganador no encontrado.' });

  const awardEvent = (db.awards || []).find((a: any) => a.id === awardId);
  const awardTitle = awardEvent?.title || 'YM-ki Music Awards';

  // Grant digital trophy
  if (!Array.isArray(profile.digitalTrophies)) profile.digitalTrophies = [];
  profile.digitalTrophies.push({
    id: 'trophy-' + Date.now(),
    awardTitle,
    categoryName: categoryId || 'Categoría Oficial',
    trophyName: trophyName || 'Trofeo de Oro YM-ki',
    icon: '🏆',
    dateAwarded: new Date().toISOString(),
    rarity: 'gold'
  });

  // Grant certificate
  if (!Array.isArray(profile.winnerCertificates)) profile.winnerCertificates = [];
  profile.winnerCertificates.push({
    id: 'cert-' + Date.now(),
    awardTitle,
    recipientName: profile.nickname || winnerKey,
    categoryName: categoryId || 'Categoría Oficial',
    issuedAt: new Date().toISOString(),
    signatureCeo: 'Dirección Oficial YM-ki'
  });

  // Add recognition title
  if (recognitionTitle) {
    if (!Array.isArray(profile.recognitionTitles)) profile.recognitionTitles = [];
    profile.recognitionTitles.push(recognitionTitle);
  }

  // Send celebratory notification
  if (!Array.isArray(db.notifications)) db.notifications = [];
  db.notifications.unshift({
    id: 'notif-' + Date.now(),
    recipient: winnerKey,
    type: 'award',
    title: '🏆 ¡Felicidades! Has recibido un Galardón Oficial',
    message: `Has sido galardonado en "${awardTitle}" con el ${trophyName}. El trofeo y tu certificado ya están en tu vitrina y perfil.`,
    date: new Date().toISOString(),
    read: false
  });

  appendAuditLog(db, {
    adminUsername: adminUser,
    action: 'GRANT_AWARD_REWARD',
    targetUser: winnerKey,
    details: `Entregó "${trophyName}" en "${awardTitle}" a @${winnerKey}`
  });

  saveDatabase(db);
  res.json({ success: true, profile: getSafeProfiles(db, winnerKey)[winnerKey] || profile, message: 'Reconocimientos y galardones digitales entregados exitosamente.' });
});

// AWARDS DELETION ENDPOINTS (ADMINS)
app.delete('/api/awards/:id', requireAuth, requireRole(['admin']), (req, res) => {
  const { id } = req.params;
  if (!Array.isArray(db.awards)) db.awards = [];
  const initialLength = db.awards.length;
  db.awards = db.awards.filter((a: any) => a.id !== id);
  saveDatabase(db);
  res.json({ success: true, deleted: db.awards.length < initialLength, awards: db.awards });
});

app.delete('/api/awards/:eventId/categories/:catId', requireAuth, requireRole(['admin']), (req, res) => {
  const { eventId, catId } = req.params;
  if (!Array.isArray(db.awards)) db.awards = [];
  const award = db.awards.find((a: any) => a.id === eventId);
  if (award && Array.isArray(award.categories)) {
    award.categories = award.categories.filter((c: any) => c.id !== catId);
    saveDatabase(db);
  }
  res.json({ success: true, awards: db.awards });
});

// PARTNERS ENDPOINTS
app.get('/api/partners', (req, res) => {
  res.json({ success: true, partners: db.partners || [] });
});

app.post('/api/partners', requireAuth, requireRole(['admin']), (req, res) => {
  const { name, logo, banner, description, links, contacts, adminNotes } = req.body;
  if (!name || !name.trim()) {
    return res.status(400).json({ error: 'Nombre de la empresa requerido.' });
  }

  const newPartner = {
    id: 'partner-' + Date.now(),
    name: name.trim(),
    logo: logo || 'https://images.unsplash.com/photo-1599305445671-ac291c95aaa9?w=150&h=150&fit=crop',
    banner: banner || 'https://images.unsplash.com/photo-1557804506-669a67965ba0?w=1200&h=400&fit=crop',
    description: description || '',
    links: Array.isArray(links) ? links : [],
    contacts: Array.isArray(contacts) ? contacts : [],
    adminNotes: adminNotes || '',
    createdAt: new Date().toISOString()
  };

  if (!Array.isArray(db.partners)) db.partners = [];
  db.partners.push(newPartner);
  saveDatabase(db);
  res.json({ success: true, partner: newPartner, partners: db.partners });
});

app.put('/api/partners/:id', requireAuth, requireRole(['admin']), (req, res) => {
  const { id } = req.params;
  const partner = (db.partners || []).find((p: any) => p.id === id);
  if (!partner) return res.status(404).json({ error: 'Empresa aliada no encontrada.' });

  const { name, logo, banner, description, links, contacts, adminNotes } = req.body;
  if (name) partner.name = name.trim();
  if (logo) partner.logo = logo;
  if (banner) partner.banner = banner;
  if (description !== undefined) partner.description = description;
  if (Array.isArray(links)) partner.links = links;
  if (Array.isArray(contacts)) partner.contacts = contacts;
  if (adminNotes !== undefined) partner.adminNotes = adminNotes;
  partner.updatedAt = new Date().toISOString();

  saveDatabase(db);
  res.json({ success: true, partner, partners: db.partners });
});

app.delete('/api/partners/:id', requireAuth, requireRole(['admin']), (req, res) => {
  const { id } = req.params;
  db.partners = (db.partners || []).filter((p: any) => p.id !== id);
  saveDatabase(db);
  res.json({ success: true, partners: db.partners });
});

// CHARTS & RANKINGS ENDPOINTS
app.get('/api/charts', (req, res) => {
  res.json({ success: true, charts: db.charts || [] });
});

app.post('/api/charts', requireAuth, requireRole(['admin']), (req, res) => {
  const { category, title, artist, coverImage, audioUrl, score, rank, previousRank, movement, period, isPublished, notes } = req.body;
  if (!title || !artist) {
    return res.status(400).json({ error: 'Título y artista requeridos para el chart.' });
  }

  const newEntry = {
    id: 'chart-' + Date.now(),
    category: category || 'main',
    title: title.trim(),
    artist: artist.trim(),
    coverImage: coverImage || 'https://images.unsplash.com/photo-1514525253161-7a46d19cd819?w=300&h=300&fit=crop',
    audioUrl: audioUrl || '',
    score: typeof score === 'number' ? score : 100,
    rank: typeof rank === 'number' ? rank : (db.charts || []).length + 1,
    previousRank: typeof previousRank === 'number' ? previousRank : rank || 1,
    movement: movement || 'new',
    period: period || 'Noviembre 2026 - Semana 1',
    isPublished: isPublished !== false,
    notes: notes || '',
    createdAt: new Date().toISOString()
  };

  if (!Array.isArray(db.charts)) db.charts = [];
  db.charts.push(newEntry);
  saveDatabase(db);
  res.json({ success: true, entry: newEntry, charts: db.charts });
});

app.put('/api/charts/:id', requireAuth, requireRole(['admin']), (req, res) => {
  const { id } = req.params;
  const entry = (db.charts || []).find((c: any) => c.id === id);
  if (!entry) return res.status(404).json({ error: 'Entrada de ranking no encontrada.' });

  Object.assign(entry, req.body);
  saveDatabase(db);
  res.json({ success: true, entry, charts: db.charts });
});

app.delete('/api/charts/:id', requireAuth, requireRole(['admin']), (req, res) => {
  const { id } = req.params;
  db.charts = (db.charts || []).filter((c: any) => c.id !== id);
  saveDatabase(db);
  res.json({ success: true, charts: db.charts });
});

// AUDITIONS SYSTEM (Server-Authoritative persistence & pass codes)
app.get('/api/auditions', requireAuth, (req, res) => {
  const user = (req as any).user;
  const isPrivileged = hasDelegatedPermission(user, db.adminDelegations, 'canManageAuditions', db.firstRegisteredUser);
  const list = isPrivileged
    ? (db.auditions || [])
    : (db.auditions || []).filter((a: any) => a?.applicantUsername?.toLowerCase() === user.username.toLowerCase());
  res.json({ success: true, auditions: list });
});

app.post('/api/auditions/submit', requireAuth, (req, res) => {
  const authUser = resolveUsernameKey(db.allProfiles, (req as any).user.username) || (req as any).user.username;
  const { applicantUsername, ceoId, ceoName, stageName, specialty, category, bio, linkUrl, videoUrl, audioUrl } = req.body;
  if (applicantUsername && applicantUsername.toLowerCase() !== authUser.toLowerCase()) {
    return res.status(403).json({ error: 'No puedes enviar audiciones en nombre de otro usuario.' });
  }
  const userProfile = db.allProfiles[authUser];
  if (!userProfile || userProfile.accountType === 'fan') {
    return res.status(403).json({
      error: 'Acceso Denegado: Las cuentas en modo Fan no tienen acceso al sistema de audiciones.'
    });
  }

  const newAud = {
    id: Date.now(),
    applicantUsername: authUser,
    ceoId: ceoId || 'ceo-primary',
    ceoName: ceoName || 'Dirección YM-ki',
    stageName: String(stageName || userProfile.nickname || authUser).trim(),
    specialty: specialty || category || 'vocal',
    bio: String(bio || '').trim(),
    linkUrl: linkUrl || videoUrl || audioUrl || '',
    date: new Date().toISOString().slice(0, 10),
    status: 'Sin calificar',
    evaluated: false,
    createdAt: new Date().toISOString()
  };

  if (!Array.isArray(db.auditions)) db.auditions = [];
  db.auditions.unshift(newAud);

  if (!Array.isArray(db.notifications)) db.notifications = [];
  db.notifications.unshift({
    id: 'notif-' + Date.now(),
    recipient: db.firstRegisteredUser || 'admin',
    sender: authUser,
    type: 'audition',
    title: 'Nueva Audición Recibida',
    message: `@${authUser} ha enviado su postulación a ${newAud.ceoName} para evaluación.`,
    auditionId: newAud.id,
    date: new Date().toISOString(),
    read: false
  });

  saveDatabase(db);
  res.json({ success: true, audition: newAud, message: 'Audición enviada y almacenada correctamente.' });
});

app.post('/api/auditions/:id/evaluate', requireAuth, requireRole(['admin']), requireDelegation('canManageAuditions'), (req, res) => {
  const reviewer = (req as any).user;
  const { id } = req.params;
  const { result, note } = req.body;
  if (!['trainee', 'artista', 'rejected', 'accepted_staff'].includes(result)) {
    return res.status(400).json({ error: 'Resultado de evaluación inválido.' });
  }

  const aud = (db.auditions || []).find((a: any) => String(a.id) === String(id));
  if (!aud) return res.status(404).json({ error: 'Audición no encontrada.' });

  let statusText = 'Calificado';
  if (result === 'trainee') statusText = 'Aceptado como Trainee';
  if (result === 'artista') statusText = 'Aceptado como Artista';
  if (result === 'accepted_staff') statusText = 'Aceptado como Staff';
  if (result === 'rejected') statusText = 'Rechazado';

  aud.status = statusText;
  aud.evaluated = true;
  aud.result = result;
  aud.evaluatorNote = String(note || '').trim();
  aud.evaluatedBy = reviewer.username;
  aud.evaluatedAt = new Date().toISOString();

  let generatedCode = '';
  let newPassCode: any = null;
  if (result === 'trainee' || result === 'artista') {
    const codePrefix = result === 'artista' ? 'YM-ART' : 'YM-TRN';
    const randDigits = crypto.randomInt(100000, 999999);
    generatedCode = `${codePrefix}-${randDigits}`;
    newPassCode = {
      code: generatedCode,
      targetUsername: aud.applicantUsername,
      role: result,
      auditionId: aud.id,
      redeemed: false,
      createdAt: new Date().toISOString()
    };
    if (!Array.isArray(db.auditionPassCodes)) db.auditionPassCodes = [];
    db.auditionPassCodes.unshift(newPassCode);
  }

  if (!Array.isArray(db.notifications)) db.notifications = [];
  db.notifications.unshift({
    id: 'notif-res-' + Date.now(),
    recipient: aud.applicantUsername,
    sender: reviewer.username,
    type: 'audition',
    title: generatedCode
      ? `🎉 ¡Audición aprobada como ${result.toUpperCase()}!`
      : 'Resultado de tu Audición',
    message: generatedCode
      ? `Tu audición fue aprobada como ${statusText}. Tu CÓDIGO OFICIAL DE ACTIVACIÓN es: "${generatedCode}".`
      : `Tu postulación fue evaluada como "${statusText}". ${aud.evaluatorNote ? `Nota: "${aud.evaluatorNote}"` : ''}`,
    auditionId: aud.id,
    date: new Date().toISOString(),
    read: false
  });

  appendAuditLog(db, {
    adminUsername: reviewer.username,
    action: 'EVALUATE_AUDITION',
    targetUser: aud.applicantUsername,
    details: `Evaluó audición #${aud.id} de @${aud.applicantUsername} -> ${statusText}`
  });

  saveDatabase(db);
  res.json({ success: true, audition: aud, passCode: newPassCode, generatedCode });
});

app.post('/api/auditions/redeem-code', requireAuth, (req, res) => {
  const authUser = resolveUsernameKey(db.allProfiles, (req as any).user.username) || (req as any).user.username;
  const cleanCode = String(req.body?.code || '').trim().toUpperCase();
  if (!cleanCode) return res.status(400).json({ error: 'Código vacío.' });

  const match = (db.auditionPassCodes || []).find((c: any) => String(c.code || '').toUpperCase() === cleanCode);
  if (!match) return res.status(404).json({ error: 'Código de activación no válido o inexistente.' });
  if (match.redeemed) return res.status(400).json({ error: 'Este código ya ha sido canjeado anteriormente.' });
  if (match.targetUsername && match.targetUsername.toLowerCase() !== authUser.toLowerCase()) {
    return res.status(403).json({ error: 'Este código fue emitido para otro usuario.' });
  }

  const profile = db.allProfiles[authUser];
  if (!profile) return res.status(404).json({ error: 'Perfil no encontrado.' });
  if (match.role !== 'trainee' && match.role !== 'artista') {
    return res.status(400).json({ error: 'Rol de código inválido.' });
  }

  match.redeemed = true;
  match.redeemedAt = new Date().toISOString();
  profile.accountType = match.role;

  appendAuditLog(db, {
    adminUsername: authUser,
    action: 'REDEEM_ROLE_CODE',
    targetUser: authUser,
    details: `Canjeó código de audición para rol "${match.role}"`
  });

  saveDatabase(db);
  res.json({
    success: true,
    profile: getSafeProfiles(db, authUser)[authUser] || profile,
    message: `¡Código verificado! Tu cuenta ahora está en modo ${match.role.toUpperCase()}.`
  });
});

// ==========================================
// 14. SISTEMA DE LOGROS, INSIGNIAS Y RECOMPENSAS API
// ==========================================
app.get('/api/achievements', (req, res) => {
  const authUser = (req as any).user?.username;
  const profile = authUser ? db.allProfiles?.[authUser] : null;
  const userProgress: Record<string, { eligible: boolean; current: number; target: number }> = {};

  if (authUser && profile) {
    for (const ach of db.achievements || []) {
      userProgress[ach.id] = evaluateAchievementEligibility(authUser, profile, ach, db);
    }
  }
  res.json({ success: true, achievements: db.achievements || [], userProgress });
});

app.post('/api/tracks/listen', requireAuth, (req, res) => {
  const authUser = resolveUsernameKey(db.allProfiles, (req as any).user.username) || (req as any).user.username;
  if (!db.missionProgress) db.missionProgress = {};
  if (!db.missionProgress[authUser]) db.missionProgress[authUser] = {};
  db.missionProgress[authUser].listen_tracks = (db.missionProgress[authUser].listen_tracks || 0) + 1;
  saveDatabase(db);
  res.json({ success: true, listenCount: db.missionProgress[authUser].listen_tracks });
});

app.post('/api/achievements', requireAuth, requireRole(['admin']), (req, res) => {
  const authUser = (req as any).user.username;
  const { title, description, category, reqType, targetCount, rewardCoins, rewardGems, rewardBadge, isSecret } = req.body;
  if (!title || !category || !reqType) {
    return res.status(400).json({ error: 'Datos de logro incompletos.' });
  }
  const newAch = {
    id: 'ach-' + Date.now(),
    title: String(title).trim(),
    description: String(description || '').trim(),
    category,
    icon: req.body.icon || '🏆',
    reqType,
    targetCount: Math.max(1, Number(targetCount) || 1),
    rewardCoins: Math.max(0, Number(rewardCoins) || 0),
    rewardGems: Math.max(0, Number(rewardGems) || 0),
    rewardBadge: rewardBadge || undefined,
    isSecret: Boolean(isSecret),
    isCustomAdminCreated: true,
    createdBy: authUser,
    createdAt: new Date().toISOString()
  };
  if (!Array.isArray(db.achievements)) db.achievements = [];
  db.achievements.push(newAch);
  appendAuditLog(db, {
    adminUsername: authUser,
    action: 'CREATE_ACHIEVEMENT',
    details: `Creó logro "${newAch.title}"`
  });
  saveDatabase(db);
  res.json({ success: true, achievement: newAch, achievements: db.achievements });
});

app.put('/api/achievements/:id', requireAuth, requireRole(['admin']), (req, res) => {
  const authUser = (req as any).user.username;
  const { id } = req.params;
  const ach = (db.achievements || []).find((a: any) => a.id === id);
  if (!ach) return res.status(404).json({ error: 'Logro no encontrado.' });
  const { title, description, category, reqType, targetCount, rewardCoins, rewardGems, rewardBadge, isSecret, icon } = req.body;
  if (title !== undefined) ach.title = String(title).trim();
  if (description !== undefined) ach.description = String(description).trim();
  if (category !== undefined) ach.category = category;
  if (reqType !== undefined) ach.reqType = reqType;
  if (targetCount !== undefined) ach.targetCount = Math.max(1, Number(targetCount) || 1);
  if (rewardCoins !== undefined) ach.rewardCoins = Math.max(0, Number(rewardCoins) || 0);
  if (rewardGems !== undefined) ach.rewardGems = Math.max(0, Number(rewardGems) || 0);
  if (rewardBadge !== undefined) ach.rewardBadge = rewardBadge;
  if (isSecret !== undefined) ach.isSecret = Boolean(isSecret);
  if (icon !== undefined) ach.icon = icon;
  appendAuditLog(db, {
    adminUsername: authUser,
    action: 'UPDATE_ACHIEVEMENT',
    details: `Actualizó logro "${ach.title}"`
  });
  saveDatabase(db);
  res.json({ success: true, achievement: ach, achievements: db.achievements });
});

app.delete('/api/achievements/:id', requireAuth, requireRole(['admin']), (req, res) => {
  const authUser = (req as any).user.username;
  const { id } = req.params;
  const target = (db.achievements || []).find((a: any) => a.id === id);
  db.achievements = (db.achievements || []).filter((a: any) => a.id !== id);
  if (target) {
    appendAuditLog(db, {
      adminUsername: authUser,
      action: 'DELETE_ACHIEVEMENT',
      details: `Eliminó logro "${target.title}"`
    });
  }
  saveDatabase(db);
  res.json({ success: true, achievements: db.achievements });
});

app.post('/api/achievements/claim', requireAuth, (req, res) => {
  const authUser = (req as any).user.username;
  const { username, achievementId } = req.body;
  if (!achievementId) return res.status(400).json({ error: 'Datos incompletos.' });
  if (username && username.toLowerCase() !== authUser.toLowerCase()) {
    return res.status(403).json({ error: 'No tienes autorización para reclamar logros en otra cuenta.' });
  }
  const effectiveUser = resolveUsernameKey(db.allProfiles, authUser) || authUser;

  const profile = db.allProfiles[effectiveUser];
  if (!profile) return res.status(404).json({ error: 'Perfil no encontrado.' });

  const ach = (db.achievements || []).find((a: any) => a.id === achievementId);
  if (!ach) return res.status(404).json({ error: 'Logro no encontrado.' });

  if (!profile.unlockedAchievements) profile.unlockedAchievements = {};
  if (profile.unlockedAchievements[achievementId]?.claimed) {
    return res.status(400).json({ error: 'Este logro ya ha sido reclamado previamente.' });
  }

  // Server-authoritative eligibility check
  const eligibility = evaluateAchievementEligibility(effectiveUser, profile, ach, db);
  if (!eligibility.eligible) {
    return res.status(400).json({
      error: `Aún no cumples los requisitos de este logro (${eligibility.current}/${eligibility.target}).`
    });
  }

  // Mark as unlocked and claimed
  profile.unlockedAchievements[achievementId] = {
    unlockedAt: new Date().toISOString(),
    claimed: true
  };

  // Grant rewards
  const rCoins = Math.max(0, Number(ach.rewardCoins) || 0);
  const rGems = Math.max(0, Number(ach.rewardGems) || 0);
  if (rCoins > 0) {
    profile.coins = (profile.coins || 0) + rCoins;
    recordLedger({
      username: effectiveUser,
      type: 'earn_coins',
      currency: 'coins',
      amount: rCoins,
      balanceAfter: profile.coins,
      reason: `Recompensa por logro: ${ach.title}`
    });
  }

  if (rGems > 0) {
    profile.gems = (profile.gems || 0) + rGems;
    recordLedger({
      username: effectiveUser,
      type: 'earn_gems',
      currency: 'gems',
      amount: rGems,
      balanceAfter: profile.gems,
      reason: `Recompensa por logro: ${ach.title}`
    });
  }

  // Grant badge if specified
  if (ach.rewardBadge) {
    if (!Array.isArray(profile.customBadges)) profile.customBadges = [];
    const hasBadge = profile.customBadges.some((b: any) => b.id === ach.rewardBadge.id);
    if (!hasBadge) {
      profile.customBadges.push({
        id: ach.rewardBadge.id,
        name: ach.rewardBadge.name,
        image: ach.rewardBadge.image,
        rarity: ach.rewardBadge.rarity || 'rara',
        unlockedAt: new Date().toISOString()
      });
    }
  }

  // Generate notification
  if (!Array.isArray(db.notifications)) db.notifications = [];
  db.notifications.unshift({
    id: 'notif-ach-' + Date.now(),
    recipient: effectiveUser,
    type: 'logros',
    category: 'logros',
    title: `🏆 ¡Logro Desbloqueado: ${ach.title}!`,
    message: `Has completado "${ach.title}". Recompensa recibida: +${rCoins} Coins y +${rGems} Gems.`,
    actionSection: 'logros',
    date: new Date().toISOString(),
    read: false
  });

  saveDatabase(db);
  res.json({ success: true, profile: getSafeProfiles(db, effectiveUser)[effectiveUser] || profile, achievement: ach, message: '¡Recompensas reclamadas con éxito!' });
});

// ==========================================
// 15. CALENDARIO GENERAL AUTOMATIZADO API
// ==========================================
app.get('/api/calendar', (req, res) => {
  // Return stored events
  res.json({ success: true, events: db.calendarEvents || [] });
});

app.post('/api/calendar', requireAuth, requireRole(['admin']), (req, res) => {
  const authUser = (req as any).user.username;
  const { name, image, description, category, startDate, endDate, time, company, relatedLink, relatedSection, isPrivate } = req.body;
  if (!name || !startDate || !category) {
    return res.status(400).json({ error: 'Nombre, fecha de inicio y categoría son requeridos.' });
  }

  const newEvent = {
    id: 'cal-event-' + Date.now(),
    name: name.trim(),
    image: image || 'https://images.unsplash.com/photo-1514525253161-7a46d19cd819?w=600&auto=format&fit=crop&q=80',
    description: (description || '').trim(),
    category,
    startDate,
    endDate: endDate || startDate,
    time: time || '12:00',
    company: company || 'YM-ki Records',
    relatedLink: relatedLink || '',
    relatedSection: relatedSection || 'calendario',
    isPrivate: Boolean(isPrivate),
    createdBy: authUser,
    isAutomated: false,
    sourceModule: 'manual',
    createdAt: new Date().toISOString()
  };

  if (!Array.isArray(db.calendarEvents)) db.calendarEvents = [];
  db.calendarEvents.unshift(newEvent);
  saveDatabase(db);
  res.json({ success: true, event: newEvent, events: db.calendarEvents });
});

app.put('/api/calendar/:id', requireAuth, requireRole(['admin']), (req, res) => {
  const { id } = req.params;
  const ev = (db.calendarEvents || []).find((e: any) => e.id === id);
  if (!ev) return res.status(404).json({ error: 'Evento no encontrado.' });

  Object.assign(ev, req.body);
  saveDatabase(db);
  res.json({ success: true, event: ev, events: db.calendarEvents });
});

app.delete('/api/calendar/:id', requireAuth, requireRole(['admin']), (req, res) => {
  const { id } = req.params;
  db.calendarEvents = (db.calendarEvents || []).filter((e: any) => e.id !== id);
  saveDatabase(db);
  res.json({ success: true, events: db.calendarEvents });
});

app.post('/api/calendar/subscribe', requireAuth, (req, res) => {
  const authUser = (req as any).user.username;
  const { username, eventId } = req.body;
  if (!eventId) return res.status(400).json({ error: 'Datos incompletos.' });
  if (username && username.toLowerCase() !== authUser.toLowerCase()) {
    return res.status(403).json({ error: 'No puedes suscribir a otro usuario a eventos.' });
  }
  const effectiveUser = authUser;

  const profile = db.allProfiles[effectiveUser];
  if (!profile) return res.status(404).json({ error: 'Perfil no encontrado.' });

  if (!Array.isArray(profile.subscribedEventIds)) profile.subscribedEventIds = [];
  const idx = profile.subscribedEventIds.indexOf(eventId);
  let subscribed = false;
  if (idx !== -1) {
    profile.subscribedEventIds.splice(idx, 1);
  } else {
    profile.subscribedEventIds.push(eventId);
    subscribed = true;
  }

  saveDatabase(db);
  res.json({ success: true, subscribed, subscribedEventIds: profile.subscribedEventIds });
});

app.post('/api/calendar/preferences', requireAuth, (req, res) => {
  const authUser = (req as any).user.username;
  const { username, preferences } = req.body;
  if (!preferences) return res.status(400).json({ error: 'Datos incompletos.' });
  if (username && username.toLowerCase() !== authUser.toLowerCase()) {
    return res.status(403).json({ error: 'No puedes modificar las preferencias de otro usuario.' });
  }
  const effectiveUser = authUser;

  const profile = db.allProfiles[effectiveUser];
  if (!profile) return res.status(404).json({ error: 'Perfil no encontrado.' });

  profile.calendarPreferences = { ...profile.calendarPreferences, ...preferences };
  saveDatabase(db);
  res.json({ success: true, preferences: profile.calendarPreferences });
});

// ==========================================
// 17. SISTEMA DE REPORTES Y MODERACIÓN API
// ==========================================
app.get('/api/moderation/reports', requireAuth, (req, res) => {
  const user = (req as any).user;
  const isModOrAdmin = hasRole(user, ['admin', 'moderador']);
  const reports = isModOrAdmin
    ? (db.userReports || [])
    : (db.userReports || []).filter(
        (r: any) =>
          r.reporterUsername?.toLowerCase() === user.username.toLowerCase() ||
          r.reportedUsername?.toLowerCase() === user.username.toLowerCase() ||
          r.reportedTargetUsername?.toLowerCase() === user.username.toLowerCase()
      );
  res.json({ success: true, reports });
});

app.get('/api/moderation/penalties', requireAuth, (req, res) => {
  const user = (req as any).user;
  const isModOrAdmin = hasRole(user, ['admin', 'moderador']);
  const penalties = isModOrAdmin
    ? (db.penaltiesHistory || [])
    : (db.penaltiesHistory || []).filter((p: any) => p.targetUsername?.toLowerCase() === user.username.toLowerCase());
  res.json({ success: true, penalties });
});

app.post('/api/moderation/action', requireAuth, requireRole(['admin', 'moderador']), (req, res) => {
  const actor = (req as any).user;
  const authUser = actor.username;
  const { reportId, actionType, targetUsername, reason, durationHours, resolutionNote } = req.body;
  if (!actionType || !targetUsername) {
    return res.status(400).json({ error: 'Datos de moderación incompletos.' });
  }

  const targetKey = resolveUsernameKey(db.allProfiles, targetUsername) || String(targetUsername).trim();
  const targetProfile = db.allProfiles[targetKey];

  if (targetProfile?.isFounder && !actor.isFounder) {
    return res.status(403).json({ error: 'No tienes autorización para sancionar a la cuenta fundadora.' });
  }
  if (targetProfile?.accountType === 'admin' && actor.accountType === 'moderador' && !actor.isFounder) {
    return res.status(403).json({ error: 'Un moderador no puede sancionar a un administrador.' });
  }

  // Update report status if provided
  if (reportId) {
    const rep = (db.userReports || []).find((r: any) => r.id === reportId);
    if (rep) {
      rep.status = actionType === 'reject' ? 'rechazado' : 'resuelto';
      rep.assignedModerator = authUser;
      rep.resolution = resolutionNote || reason || actionType;
      rep.penaltyApplied = actionType;
      rep.updatedAt = new Date().toISOString();
    }
  }

  const parsedHours = durationHours ? Number(durationHours) : 0;
  // Record penalty
  const newPenalty = {
    id: 'pen-' + Date.now(),
    targetUsername: targetKey,
    type: actionType,
    reason: reason || 'Incumplimiento de las normas comunitarias.',
    appliedBy: authUser,
    appliedAt: new Date().toISOString(),
    expiresAt: parsedHours > 0 ? new Date(Date.now() + parsedHours * 3600 * 1000).toISOString() : undefined,
    status: 'activa'
  };

  if (!Array.isArray(db.penaltiesHistory)) db.penaltiesHistory = [];
  db.penaltiesHistory.unshift(newPenalty);

  // Apply effect to target user profile
  if (targetProfile) {
    if (actionType === 'temp_ban' || actionType === 'suspend_user') {
      targetProfile.isSuspended = true;
      targetProfile.suspensionReason = reason || 'Suspensión temporal por moderación.';
      targetProfile.suspensionExpires = newPenalty.expiresAt;
      revokeUserSessions(db.activeSessions, targetKey);
    } else if (actionType === 'perm_ban') {
      targetProfile.isSuspended = true;
      targetProfile.suspensionReason = 'Sanción definitiva permanente: ' + (reason || 'Incumplimiento grave');
      targetProfile.suspensionExpires = 'permanente';
      revokeUserSessions(db.activeSessions, targetKey);
    }
  }

  appendAuditLog(db, {
    adminUsername: authUser,
    action: `MODERATION_${String(actionType).toUpperCase()}`,
    targetUser: targetKey,
    details: `Acción de moderación "${actionType}" sobre @${targetKey}: ${reason || resolutionNote || 'Sin detalles'}`
  });

  // Notify target user
  if (!Array.isArray(db.notifications)) db.notifications = [];
  db.notifications.unshift({
    id: 'notif-mod-' + Date.now(),
    recipient: targetKey,
    type: 'moderacion',
    category: 'moderacion',
    title: '🛡️ Aviso del Equipo de Moderación',
    message: `Se ha registrado una acción (${actionType}): "${reason || 'Revisión administrativa'}".`,
    date: new Date().toISOString(),
    read: false
  });

  saveDatabase(db);
  res.json({ success: true, penalty: newPenalty, reports: db.userReports, penalties: db.penaltiesHistory });
});

app.post('/api/moderation/appeal', requireAuth, (req, res) => {
  const authUser = (req as any).user.username;
  const { penaltyId, username, appealText } = req.body;
  if (!penaltyId || !appealText) {
    return res.status(400).json({ error: 'Texto de apelación requerido.' });
  }
  if (username && username.toLowerCase() !== authUser.toLowerCase()) {
    return res.status(403).json({ error: 'No puedes presentar apelaciones en nombre de otro usuario.' });
  }

  const pen = (db.penaltiesHistory || []).find((p: any) => p.id === penaltyId);
  if (!pen) return res.status(404).json({ error: 'Sanción no encontrada.' });
  if (pen.targetUsername?.toLowerCase() !== authUser.toLowerCase()) {
    return res.status(403).json({ error: 'Solo el usuario sancionado puede apelar esta sanción.' });
  }

  pen.status = 'apelada';
  pen.appeal = {
    text: String(appealText).trim(),
    submittedAt: new Date().toISOString(),
    status: 'pending'
  };

  // Notify Founder
  if (!Array.isArray(db.notifications)) db.notifications = [];
  db.notifications.unshift({
    id: 'notif-app-' + Date.now(),
    recipient: db.firstRegisteredUser || 'admin',
    type: 'moderacion',
    category: 'moderacion',
    title: '⚖️ Nueva Apelación de Usuario',
    message: `@${authUser} presentó una apelación contra la sanción "${pen.type}".`,
    date: new Date().toISOString(),
    read: false
  });

  saveDatabase(db);
  res.json({ success: true, penalty: pen, message: 'Tu apelación ha sido enviada para revisión de los administradores.' });
});

app.post('/api/moderation/review-appeal', requireAuth, requireRole(['admin', 'moderador']), (req, res) => {
  const authUser = (req as any).user.username;
  const { penaltyId, decision, responseText } = req.body;
  if (!penaltyId || !decision) return res.status(400).json({ error: 'Decisión requerida.' });

  const pen = (db.penaltiesHistory || []).find((p: any) => p.id === penaltyId);
  if (!pen || !pen.appeal) return res.status(404).json({ error: 'Apelación no encontrada.' });

  pen.appeal.status = decision === 'accept' ? 'accepted' : 'rejected';
  pen.appeal.response = responseText || '';
  pen.appeal.reviewedBy = authUser;

  const targetKey = resolveUsernameKey(db.allProfiles, pen.targetUsername) || pen.targetUsername;
  if (decision === 'accept') {
    pen.status = 'revocada';
    const profile = db.allProfiles[targetKey];
    if (profile) {
      profile.isSuspended = false;
      delete profile.suspensionReason;
      delete profile.suspensionExpires;
    }
  }

  appendAuditLog(db, {
    adminUsername: authUser,
    action: decision === 'accept' ? 'ACCEPT_APPEAL' : 'REJECT_APPEAL',
    targetUser: targetKey,
    details: `Apelación ${decision === 'accept' ? 'aceptada' : 'rechazada'} para @${targetKey}`
  });

  // Notify user
  if (!Array.isArray(db.notifications)) db.notifications = [];
  db.notifications.unshift({
    id: 'notif-appres-' + Date.now(),
    recipient: targetKey,
    type: 'moderacion',
    category: 'moderacion',
    title: decision === 'accept' ? '✅ Apelación Aceptada' : '❌ Apelación Desestimada',
    message: `Tu apelación fue revisada por @${authUser}: ${responseText || (decision === 'accept' ? 'La sanción fue revocada.' : 'La sanción se mantiene.')}`,
    date: new Date().toISOString(),
    read: false
  });

  saveDatabase(db);
  res.json({ success: true, penalty: pen, penalties: db.penaltiesHistory });
});

// ==========================================
// 18. SISTEMA DE COLABORACIONES API
// ==========================================
app.get('/api/collaborations', (req, res) => {
  res.json({ success: true, collaborations: db.collaborations || [] });
});

app.post('/api/collaborations', requireAuth, (req, res) => {
  const authUser = (req as any).user.username;
  const {
    projectName,
    type,
    description,
    objective,
    creatorUsername,
    targetUsernameOrCompany,
    isCompanyCollaboration,
    companyA,
    companyB,
    startDate,
    endDate,
    requirements,
    attachments
  } = req.body;

  if (creatorUsername && creatorUsername.toLowerCase() !== authUser.toLowerCase()) {
    return res.status(403).json({ error: 'No puedes crear colaboraciones en nombre de otro usuario.' });
  }
  const effectiveCreator = authUser;

  if (!projectName || !type || !description || !targetUsernameOrCompany) {
    return res.status(400).json({ error: 'Faltan campos obligatorios para la propuesta de colaboración.' });
  }

  const newCollab = {
    id: 'collab-' + Date.now(),
    projectName: projectName.trim(),
    type,
    description: description.trim(),
    objective: (objective || '').trim(),
    creatorUsername: effectiveCreator,
    targetUsernameOrCompany,
    isCompanyCollaboration: Boolean(isCompanyCollaboration),
    companyA: companyA || undefined,
    companyB: companyB || undefined,
    startDate: startDate || new Date().toISOString().split('T')[0],
    endDate: endDate || undefined,
    requirements: requirements || undefined,
    attachments: Array.isArray(attachments) ? attachments : [],
    status: 'enviada',
    participants: [effectiveCreator],
    publicShowcase: false,
    progressUpdates: [],
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString()
  };

  if (!Array.isArray(db.collaborations)) db.collaborations = [];
  db.collaborations.unshift(newCollab);

  // Notify recipient user or company leader
  if (!Array.isArray(db.notifications)) db.notifications = [];
  db.notifications.unshift({
    id: 'notif-collab-' + Date.now(),
    recipient: targetUsernameOrCompany,
    type: 'colaboraciones',
    category: 'colaboraciones',
    title: '🤝 Nueva Propuesta de Colaboración',
    message: `@${effectiveCreator} te ha enviado la propuesta "${projectName}" (${type}).`,
    actionSection: 'colaboraciones',
    date: new Date().toISOString(),
    read: false
  });

  saveDatabase(db);
  res.json({ success: true, collaboration: newCollab, collaborations: db.collaborations });
});

app.put('/api/collaborations/:id/status', requireAuth, (req, res) => {
  const { id } = req.params;
  const authUser = (req as any).user.username;
  const isAdmin = (req as any).user.isFounder || (req as any).user.accountType === 'admin';
  const { status } = req.body;
  if (!status) return res.status(400).json({ error: 'Nuevo estado requerido.' });

  const collab = (db.collaborations || []).find((c: any) => c.id === id);
  if (!collab) return res.status(404).json({ error: 'Colaboración no encontrada.' });

  const isInvolved =
    isAdmin ||
    collab.creatorUsername?.toLowerCase() === authUser.toLowerCase() ||
    collab.targetUsernameOrCompany?.toLowerCase() === authUser.toLowerCase() ||
    (Array.isArray(collab.participants) && collab.participants.some((p: string) => p.toLowerCase() === authUser.toLowerCase()));
  if (!isInvolved) {
    return res.status(403).json({ error: 'No tienes autorización para actualizar esta colaboración.' });
  }

  collab.status = status;
  collab.updatedAt = new Date().toISOString();

  // If accepted, add target user to participants and automatically create a dedicated project chat group!
  if (status === 'aceptada' || status === 'en_desarrollo') {
    if (!Array.isArray(collab.participants)) collab.participants = [collab.creatorUsername];
    if (!collab.participants.includes(collab.targetUsernameOrCompany)) {
      collab.participants.push(collab.targetUsernameOrCompany);
    }

    if (!collab.chatGroupId) {
      const projectChatGroup = {
        id: 'group-collab-' + collab.id,
        name: `Proyecto: ${collab.projectName}`,
        icon: '🤝',
        category: 'colaboracion',
        duration: 'permanent',
        isAdvanced: true,
        admins: [collab.creatorUsername, collab.targetUsernameOrCompany],
        members: Array.from(new Set([...collab.participants, collab.creatorUsername, collab.targetUsernameOrCompany])),
        categories: [
          {
            id: 'cat-collab-general',
            name: 'Canales del Proyecto',
            subgroups: [
              {
                id: 'sub-collab-chat',
                name: 'chat-general',
                icon: '💬',
                type: 'general',
                messages: [
                  {
                    id: 'msg-start-' + Date.now(),
                    sender: 'Sistema',
                    text: `¡Colaboración "${collab.projectName}" iniciada oficialmente entre @${collab.creatorUsername} y @${collab.targetUsernameOrCompany}!`,
                    timestamp: new Date().toISOString()
                  }
                ]
              },
              {
                id: 'sub-collab-files',
                name: 'archivos-y-avances',
                icon: '📁',
                type: 'tasks',
                messages: []
              }
            ]
          }
        ],
        createdAt: new Date().toISOString()
      };

      if (!Array.isArray(db.chatGroups)) db.chatGroups = [];
      db.chatGroups.unshift(projectChatGroup);
      collab.chatGroupId = projectChatGroup.id;
    }

    // Notify participants
    if (!Array.isArray(db.notifications)) db.notifications = [];
    for (const p of collab.participants) {
      db.notifications.unshift({
        id: 'notif-collab-acc-' + Date.now() + '-' + Math.random(),
        recipient: p,
        type: 'colaboraciones',
        category: 'colaboraciones',
        title: '🎉 Colaboración Aceptada',
        message: `El proyecto "${collab.projectName}" ha sido aceptado y su espacio de trabajo y chat están listos.`,
        actionSection: 'colaboraciones',
        date: new Date().toISOString(),
        read: false
      });
    }
  }

  saveDatabase(db);
  res.json({ success: true, collaboration: collab, collaborations: db.collaborations, chatGroups: db.chatGroups });
});

app.post('/api/collaborations/:id/update', requireAuth, (req, res) => {
  const { id } = req.params;
  const authUser = (req as any).user.username;
  const isAdmin = (req as any).user.isFounder || (req as any).user.accountType === 'admin';
  const { text, fileUrl } = req.body;
  if (!text) return res.status(400).json({ error: 'Contenido requerido.' });

  const collab = (db.collaborations || []).find((c: any) => c.id === id);
  if (!collab) return res.status(404).json({ error: 'Colaboración no encontrada.' });

  const isInvolved =
    isAdmin ||
    collab.creatorUsername?.toLowerCase() === authUser.toLowerCase() ||
    collab.targetUsernameOrCompany?.toLowerCase() === authUser.toLowerCase() ||
    (Array.isArray(collab.participants) && collab.participants.some((p: string) => p.toLowerCase() === authUser.toLowerCase()));
  if (!isInvolved) {
    return res.status(403).json({ error: 'Solo los participantes de la colaboración pueden publicar avances.' });
  }

  if (!Array.isArray(collab.progressUpdates)) collab.progressUpdates = [];
  const update = {
    id: 'upd-' + Date.now(),
    author: authUser,
    text: text.trim(),
    fileUrl: fileUrl || undefined,
    timestamp: new Date().toISOString()
  };
  collab.progressUpdates.push(update);
  collab.updatedAt = new Date().toISOString();

  saveDatabase(db);
  res.json({ success: true, update, collaboration: collab });
});

app.put('/api/collaborations/:id/showcase', requireAuth, (req, res) => {
  const { id } = req.params;
  const authUser = (req as any).user.username;
  const isAdmin = (req as any).user.isFounder || (req as any).user.accountType === 'admin';
  const { publicShowcase } = req.body;

  const collab = (db.collaborations || []).find((c: any) => c.id === id);
  if (!collab) return res.status(404).json({ error: 'Colaboración no encontrada.' });

  const isInvolved =
    isAdmin ||
    collab.creatorUsername?.toLowerCase() === authUser.toLowerCase() ||
    collab.targetUsernameOrCompany?.toLowerCase() === authUser.toLowerCase() ||
    (Array.isArray(collab.participants) && collab.participants.some((p: string) => p.toLowerCase() === authUser.toLowerCase()));
  if (!isInvolved) {
    return res.status(403).json({ error: 'No tienes autorización para cambiar la visibilidad de esta colaboración.' });
  }

  collab.publicShowcase = Boolean(publicShowcase);
  collab.updatedAt = new Date().toISOString();

  saveDatabase(db);
  res.json({ success: true, collaboration: collab });
});

// ==========================================
// 18.1 CHATS EDIT & DELETE ACTIONS
// ==========================================
app.put('/api/chats/message/:messageId', requireAuth, (req, res) => {
  const { messageId } = req.params;
  const authUser = (req as any).user.username;
  const isAdmin = (req as any).user.isFounder || (req as any).user.accountType === 'admin';
  const { newText } = req.body;
  if (!newText) return res.status(400).json({ error: 'Datos incompletos.' });

  let found = false;
  // Search in direct chats
  for (const [key, msgList] of Object.entries(db.chats || {})) {
    if (Array.isArray(msgList)) {
      const msg = msgList.find((m: any) => m.id === messageId);
      if (msg) {
        if (msg.from?.toLowerCase() !== authUser.toLowerCase() && !isAdmin) {
          return res.status(403).json({ error: 'Solo puedes editar tus propios mensajes.' });
        }
        msg.text = newText;
        msg.isEdited = true;
        msg.editedAt = new Date().toISOString();
        found = true;
        break;
      }
    }
  }

  // Search in group chats
  if (!found) {
    for (const group of db.chatGroups || []) {
      for (const cat of group.categories || []) {
        for (const sub of cat.subgroups || []) {
          const msg = (sub.messages || []).find((m: any) => m.id === messageId);
          if (msg) {
            if (msg.sender?.toLowerCase() !== authUser.toLowerCase() && !isAdmin) {
              return res.status(403).json({ error: 'Solo puedes editar tus propios mensajes.' });
            }
            msg.text = newText;
            msg.isEdited = true;
            msg.editedAt = new Date().toISOString();
            found = true;
            break;
          }
        }
        if (found) break;
      }
      if (found) break;
    }
  }

  if (!found) return res.status(404).json({ error: 'Mensaje no encontrado.' });
  saveDatabase(db);
  res.json({ success: true, message: 'Mensaje editado con éxito.' });
});

app.delete('/api/chats/message/:messageId', requireAuth, (req, res) => {
  const { messageId } = req.params;
  const authUser = (req as any).user.username;
  const isAdmin = (req as any).user.isFounder || (req as any).user.accountType === 'admin';

  let found = false;
  // Direct chats
  for (const [key, msgList] of Object.entries(db.chats || {})) {
    if (Array.isArray(msgList)) {
      const idx = msgList.findIndex((m: any) => m.id === messageId);
      if (idx !== -1) {
        if (msgList[idx].from?.toLowerCase() !== authUser.toLowerCase() && !isAdmin) {
          return res.status(403).json({ error: 'Solo puedes eliminar tus propios mensajes.' });
        }
        msgList.splice(idx, 1);
        found = true;
        break;
      }
    }
  }

  // Groups
  if (!found) {
    for (const group of db.chatGroups || []) {
      for (const cat of group.categories || []) {
        for (const sub of cat.subgroups || []) {
          const idx = (sub.messages || []).findIndex((m: any) => m.id === messageId);
          if (idx !== -1) {
            if (sub.messages[idx].sender?.toLowerCase() !== authUser.toLowerCase() && !isAdmin) {
              return res.status(403).json({ error: 'Solo puedes eliminar tus propios mensajes.' });
            }
            sub.messages.splice(idx, 1);
            found = true;
            break;
          }
        }
        if (found) break;
      }
      if (found) break;
    }
  }

  if (!found) return res.status(404).json({ error: 'Mensaje no encontrado.' });
  saveDatabase(db);
  res.json({ success: true, message: 'Mensaje eliminado con éxito.' });
});

// ==========================================
// 19. SISTEMA DE SEGUIDORES (FOLLOWERS API)
// ==========================================
app.get('/api/followers/:username', (req, res) => {
  const { username } = req.params;
  const followersList = (db.followers || []).filter((f) => f?.followingUsername?.toLowerCase() === username.toLowerCase());
  const followingList = (db.followers || []).filter((f) => f?.followerUsername?.toLowerCase() === username.toLowerCase());

  res.json({
    success: true,
    username,
    followersCount: followersList.length,
    followingCount: followingList.length,
    followers: followersList.map((f) => ({
      username: f.followerUsername,
      profile: getSafeProfiles(db)[f.followerUsername] || null,
      followedAt: f.followedAt
    })),
    following: followingList.map((f) => ({
      username: f.followingUsername,
      profile: getSafeProfiles(db)[f.followingUsername] || null,
      followedAt: f.followedAt
    }))
  });
});

app.post('/api/followers/follow', requireAuth, (req, res) => {
  const authUser = (req as any).user.username;
  const { followerUsername, targetUsername } = req.body;
  if (!targetUsername) {
    return res.status(400).json({ error: 'Faltan parámetros requeridos.' });
  }
  if (followerUsername && followerUsername.toLowerCase() !== authUser.toLowerCase()) {
    return res.status(403).json({ error: 'No puedes seguir usuarios en nombre de otra cuenta.' });
  }
  const effectiveFollower = authUser;

  if (effectiveFollower.toLowerCase() === targetUsername.toLowerCase()) {
    return res.status(400).json({ error: 'No puedes seguirte a ti mismo.' });
  }

  // Check if target has blocked the follower
  if (!db.blockedUsers) db.blockedUsers = {};
  const targetBlocked = (db.blockedUsers[targetUsername] || []).includes(effectiveFollower);
  if (targetBlocked) {
    return res.status(403).json({ error: 'No puedes interactuar con este usuario debido a bloqueos.' });
  }

  if (!Array.isArray(db.followers)) db.followers = [];
  const exists = db.followers.some(
    (f) => f?.followerUsername?.toLowerCase() === effectiveFollower.toLowerCase() &&
           f?.followingUsername?.toLowerCase() === targetUsername.toLowerCase()
  );

  if (exists) {
    return res.json({ success: true, message: 'Ya sigues a este usuario.', isFollowing: true });
  }

  const newRelation = {
    id: 'fol-' + Date.now() + '-' + Math.floor(Math.random() * 1000),
    followerUsername: effectiveFollower,
    followingUsername: targetUsername,
    followedAt: new Date().toISOString()
  };
  db.followers.push(newRelation);

  // Send notification to target
  if (!Array.isArray(db.notifications)) db.notifications = [];
  db.notifications.unshift({
    id: 'notif-' + Date.now(),
    recipient: targetUsername,
    sender: effectiveFollower,
    type: 'new_follower',
    category: 'cuenta',
    title: 'Nuevo seguidor',
    message: `@${effectiveFollower} ha comenzado a seguir tu perfil.`,
    relatedId: effectiveFollower,
    date: new Date().toISOString(),
    read: false
  });

  saveDatabase(db);
  res.json({ success: true, message: `Ahora sigues a @${targetUsername}.`, isFollowing: true });
});

app.post('/api/followers/unfollow', requireAuth, (req, res) => {
  const authUser = (req as any).user.username;
  const { followerUsername, targetUsername } = req.body;
  if (!targetUsername) {
    return res.status(400).json({ error: 'Faltan parámetros requeridos.' });
  }
  if (followerUsername && followerUsername.toLowerCase() !== authUser.toLowerCase()) {
    return res.status(403).json({ error: 'No puedes dejar de seguir usuarios en nombre de otra cuenta.' });
  }
  const effectiveFollower = authUser;

  if (!Array.isArray(db.followers)) db.followers = [];
  const idx = db.followers.findIndex(
    (f) => f?.followerUsername?.toLowerCase() === effectiveFollower.toLowerCase() &&
           f?.followingUsername?.toLowerCase() === targetUsername.toLowerCase()
  );

  if (idx !== -1) {
    db.followers.splice(idx, 1);
    saveDatabase(db);
  }

  res.json({ success: true, message: `Has dejado de seguir a @${targetUsername}.`, isFollowing: false });
});

// ==========================================
// 20. ESTADOS PERSONALIZADOS (USER STATUS)
// ==========================================
app.get('/api/status/:username', (req, res) => {
  const { username } = req.params;
  const status = db.userStatuses?.[username];
  if (!status) return res.json({ status: null });

  // Check expiration if set
  if (status.expiresAt && new Date(status.expiresAt).getTime() < Date.now()) {
    delete db.userStatuses[username];
    saveDatabase(db);
    return res.json({ status: null });
  }

  res.json({ status });
});

app.post('/api/status', requireAuth, (req, res) => {
  const authUser = (req as any).user.username;
  const { username, text, emoji, visibility, durationHours } = req.body;
  if (!text) {
    return res.status(400).json({ error: 'Texto de estado requerido.' });
  }
  if (username && username.toLowerCase() !== authUser.toLowerCase()) {
    return res.status(403).json({ error: 'No tienes autorización para cambiar el estado de otro usuario.' });
  }
  const targetUser = authUser;

  if (!db.userStatuses) db.userStatuses = {};
  let expiresAt: string | null = null;
  if (durationHours && Number(durationHours) > 0) {
    expiresAt = new Date(Date.now() + Number(durationHours) * 3600 * 1000).toISOString();
  }

  const newStatus = {
    username: targetUser,
    text: text.trim().slice(0, 100),
    emoji: emoji || '✨',
    visibility: visibility || 'public',
    expiresAt,
    updatedAt: new Date().toISOString()
  };

  db.userStatuses[targetUser] = newStatus;
  if (db.allProfiles[targetUser]) {
    db.allProfiles[targetUser].userStatus = newStatus;
  }

  saveDatabase(db);
  res.json({ success: true, status: newStatus });
});

app.delete('/api/status/:username', requireAuth, (req, res) => {
  const { username } = req.params;
  const authUser = (req as any).user.username;
  const isAdmin = (req as any).user.isFounder || (req as any).user.accountType === 'admin';
  if (username.toLowerCase() !== authUser.toLowerCase() && !isAdmin) {
    return res.status(403).json({ error: 'No tienes autorización para eliminar el estado de otro usuario.' });
  }
  const key = Object.keys(db.userStatuses || {}).find((k) => k.toLowerCase() === username.toLowerCase()) || username;
  if (db.userStatuses && db.userStatuses[key]) {
    delete db.userStatuses[key];
    if (db.allProfiles[key]) {
      db.allProfiles[key].userStatus = null;
    }
    saveDatabase(db);
  }
  res.json({ success: true, message: 'Estado eliminado.' });
});

// ==========================================
// 21. REACCIONES A PUBLICACIONES & COMENTARIOS
// ==========================================
const ALLOWED_REACTIONS = ['like', 'love', 'laugh', 'wow', 'fire', 'support', 'cute'];

app.post('/api/posts/:id/react', requireAuth, (req, res) => {
  const postId = Number(req.params.id);
  const authUser = (req as any).user.username;
  const { username, reaction } = req.body;
  if (!reaction || !ALLOWED_REACTIONS.includes(reaction)) {
    return res.status(400).json({ error: 'Reacción no válida.' });
  }
  if (username && username.toLowerCase() !== authUser.toLowerCase()) {
    return res.status(403).json({ error: 'No puedes reaccionar en nombre de otro usuario.' });
  }
  const effectiveUser = authUser;

  const post = (db.posts || []).find((p) => Number(p.id) === postId);
  if (!post) return res.status(404).json({ error: 'Publicación no encontrada.' });

  if (!post.reactions) post.reactions = {};
  if (!post.reactionCounts) post.reactionCounts = {};

  const prevReaction = post.reactions[effectiveUser];
  if (prevReaction === reaction) {
    // Toggle off
    delete post.reactions[effectiveUser];
    post.reactionCounts[reaction] = Math.max(0, (post.reactionCounts[reaction] || 1) - 1);
  } else {
    // If was another reaction, decrement it
    if (prevReaction && post.reactionCounts[prevReaction]) {
      post.reactionCounts[prevReaction] = Math.max(0, post.reactionCounts[prevReaction] - 1);
    }
    post.reactions[effectiveUser] = reaction;
    post.reactionCounts[reaction] = (post.reactionCounts[reaction] || 0) + 1;

    // Send notification to author if reacting for first time
    if (post.author && post.author !== effectiveUser) {
      if (!Array.isArray(db.notifications)) db.notifications = [];
      db.notifications.unshift({
        id: 'notif-' + Date.now(),
        recipient: post.author,
        sender: effectiveUser,
        type: 'post_reaction',
        category: 'community',
        title: 'Nueva reacción a tu publicación',
        message: `@${effectiveUser} reaccionó a "${(post.title || 'Publicación').slice(0, 30)}..."`,
        relatedId: String(post.id),
        date: new Date().toISOString(),
        read: false
      });
    }
  }

  // Recalculate traditional likes count for backwards compatibility
  post.likes = Object.keys(post.reactions).length;

  saveDatabase(db);
  res.json({
    success: true,
    reactions: post.reactions,
    reactionCounts: post.reactionCounts,
    myReaction: post.reactions[effectiveUser] || null
  });
});

// Nested Comments & Replies
app.post('/api/posts/:id/comments', requireAuth, (req, res) => {
  const postId = Number(req.params.id);
  const authUser = (req as any).user.username;
  const { author, text, parentCommentId } = req.body;
  if (!text || !text.trim()) {
    return res.status(400).json({ error: 'Contenido del comentario requerido.' });
  }
  if (author && author.toLowerCase() !== authUser.toLowerCase()) {
    return res.status(403).json({ error: 'No puedes comentar en nombre de otro usuario.' });
  }
  const effectiveAuthor = authUser;

  const post = (db.posts || []).find((p) => Number(p.id) === postId);
  if (!post) return res.status(404).json({ error: 'Publicación no encontrada.' });

  if (!Array.isArray(post.comments)) post.comments = [];
  if (!Array.isArray(post.nestedComments)) post.nestedComments = [];

  const newComment = {
    id: 'cmt-' + Date.now() + '-' + Math.floor(Math.random() * 1000),
    postId,
    author: effectiveAuthor,
    text: text.trim(),
    parentCommentId: parentCommentId || null,
    timestamp: new Date().toISOString(),
    isEdited: false,
    reactions: {},
    reactionCounts: {},
    replies: []
  };

  if (parentCommentId) {
    // Find parent in nested comments
    const findAndAppend = (list: any[]): boolean => {
      for (const item of list) {
        if (item.id === parentCommentId) {
          if (!Array.isArray(item.replies)) item.replies = [];
          item.replies.push(newComment);
          return true;
        }
        if (item.replies && item.replies.length > 0) {
          if (findAndAppend(item.replies)) return true;
        }
      }
      return false;
    };

    const found = findAndAppend(post.nestedComments);
    if (!found) {
      post.nestedComments.push(newComment);
    }
  } else {
    post.nestedComments.push(newComment);
  }

  // Also push to flat comments array for backwards compatibility
  post.comments.push({
    author: effectiveAuthor,
    text: text.trim(),
    timestamp: newComment.timestamp
  });

  if (!Array.isArray(db.notifications)) db.notifications = [];

  // Check for @mentions in comment text
  const mentions = text.match(/@([a-zA-Z0-9_\-]+)/g) || [];
  for (const m of mentions) {
    const targetUser = m.slice(1);
    if (db.allProfiles[targetUser] && targetUser !== effectiveAuthor) {
      db.notifications.unshift({
        id: 'notif-m-' + Date.now() + '-' + Math.floor(Math.random() * 1000),
        recipient: targetUser,
        sender: effectiveAuthor,
        type: 'mention',
        category: 'community',
        title: 'Te han mencionado',
        message: `@${effectiveAuthor} te mencionó en un comentario de "${(post.title || 'Publicación').slice(0, 30)}..."`,
        relatedId: String(post.id),
        date: new Date().toISOString(),
        read: false
      });
    }
  }

  // Notify post author if different
  if (post.author && post.author !== effectiveAuthor) {
    db.notifications.unshift({
      id: 'notif-' + Date.now(),
      recipient: post.author,
      sender: effectiveAuthor,
      type: 'new_comment',
      category: 'community',
      title: 'Nuevo comentario en tu publicación',
      message: `@${effectiveAuthor} comentó: "${text.trim().slice(0, 50)}..."`,
      relatedId: String(post.id),
      date: new Date().toISOString(),
      read: false
    });
  }

  saveDatabase(db);
  res.json({ success: true, comment: newComment, nestedComments: post.nestedComments });
});

// Edit Comment
app.put('/api/posts/:id/comments/:commentId', requireAuth, (req, res) => {
  const postId = Number(req.params.id);
  const { commentId } = req.params;
  const authUser = (req as any).user.username;
  const isAdmin = (req as any).user.isFounder || (req as any).user.accountType === 'admin';
  const { text } = req.body;
  if (!text || !String(text).trim()) return res.status(400).json({ error: 'Texto requerido.' });

  const post = (db.posts || []).find((p) => Number(p.id) === postId);
  if (!post) return res.status(404).json({ error: 'Publicación no encontrada.' });

  const findAndEdit = (list: any[]): boolean => {
    for (const c of list) {
      if (c.id === commentId) {
        if (c.author?.toLowerCase() !== authUser.toLowerCase() && !isAdmin) {
          return false;
        }
        c.text = String(text).trim();
        c.isEdited = true;
        c.editedAt = new Date().toISOString();
        return true;
      }
      if (c.replies && findAndEdit(c.replies)) return true;
    }
    return false;
  };

  const ok = findAndEdit(post.nestedComments || []);
  if (!ok) return res.status(403).json({ error: 'No autorizado o comentario no encontrado.' });

  saveDatabase(db);
  res.json({ success: true, nestedComments: post.nestedComments });
});

// Delete Comment
app.delete('/api/posts/:id/comments/:commentId', requireAuth, (req, res) => {
  const postId = Number(req.params.id);
  const { commentId } = req.params;
  const authUser = (req as any).user.username;
  const isAdmin = (req as any).user.isFounder || (req as any).user.accountType === 'admin';

  const post = (db.posts || []).find((p) => Number(p.id) === postId);
  if (!post) return res.status(404).json({ error: 'Publicación no encontrada.' });

  const findAndDelete = (list: any[]): boolean => {
    for (let i = 0; i < list.length; i++) {
      if (list[i].id === commentId) {
        if (
          list[i].author?.toLowerCase() !== authUser.toLowerCase() &&
          post.author?.toLowerCase() !== authUser.toLowerCase() &&
          !isAdmin
        ) {
          return false;
        }
        list.splice(i, 1);
        return true;
      }
      if (list[i].replies && findAndDelete(list[i].replies)) return true;
    }
    return false;
  };

  const ok = findAndDelete(post.nestedComments || []);
  if (!ok) return res.status(403).json({ error: 'No autorizado o comentario no encontrado.' });

  saveDatabase(db);
  res.json({ success: true, nestedComments: post.nestedComments });
});

// ==========================================
// 22. ENCUESTAS COMUNITARIAS (COMMUNITY POLLS)
// ==========================================
app.post('/api/posts/:id/poll/vote', requireAuth, (req, res) => {
  const postId = Number(req.params.id);
  const authUser = (req as any).user.username;
  const { username, optionId } = req.body;
  if (!optionId) {
    return res.status(400).json({ error: 'Datos incompletos.' });
  }
  if (username && username.toLowerCase() !== authUser.toLowerCase()) {
    return res.status(403).json({ error: 'No puedes votar en nombre de otro usuario.' });
  }
  const effectiveUser = authUser;

  const post = (db.posts || []).find((p) => Number(p.id) === postId);
  if (!post || !post.pollData) return res.status(404).json({ error: 'Encuesta no encontrada en esta publicación.' });

  const poll = post.pollData;
  if (poll.expiresAt && new Date(poll.expiresAt).getTime() < Date.now()) {
    return res.status(400).json({ error: 'Esta encuesta ya ha finalizado.' });
  }

  if (!poll.voters) poll.voters = {};
  const previousVote = poll.voters[effectiveUser];

  if (previousVote === optionId) {
    // Already voted this option
    return res.json({ success: true, pollData: poll });
  }

  if (previousVote && !poll.allowChangeVote) {
    return res.status(400).json({ error: 'Ya has votado en esta encuesta y no se permite cambiar el voto.' });
  }

  // Adjust counts
  if (previousVote) {
    const prevOpt = poll.options.find((o: any) => o.id === previousVote);
    if (prevOpt) prevOpt.votesCount = Math.max(0, (prevOpt.votesCount || 1) - 1);
  }

  const opt = poll.options.find((o: any) => o.id === optionId);
  if (!opt) return res.status(404).json({ error: 'Opción no válida.' });

  opt.votesCount = (opt.votesCount || 0) + 1;
  poll.voters[effectiveUser] = optionId;

  // Recalculate totals and percentages
  poll.totalVotes = poll.options.reduce((sum: number, o: any) => sum + (o.votesCount || 0), 0);
  for (const o of poll.options) {
    o.percentage = poll.totalVotes > 0 ? Math.round((o.votesCount / poll.totalVotes) * 100) : 0;
  }

  saveDatabase(db);
  res.json({ success: true, pollData: poll });
});

// ==========================================
// 23. PUBLICACIONES GUARDADAS Y COLECCIONES
// ==========================================
app.get('/api/saved/collections/:username', requireAuth, (req, res) => {
  const { username } = req.params;
  const authUser = (req as any).user.username;
  const isAdmin = (req as any).user.isFounder || (req as any).user.accountType === 'admin';
  if (username.toLowerCase() !== authUser.toLowerCase() && !isAdmin) {
    return res.status(403).json({ error: 'No tienes autorización para ver las colecciones privadas de otro usuario.' });
  }
  const collections = db.savedCollections?.[username] || [
    { id: 'col-default', username, name: 'Favoritos generales', description: 'Publicaciones y temas guardados', createdAt: new Date().toISOString() }
  ];
  res.json({ success: true, collections });
});

app.post('/api/saved/collections', requireAuth, (req, res) => {
  const authUser = (req as any).user.username;
  const { username, name, description } = req.body;
  if (!name) return res.status(400).json({ error: 'Nombre de colección requerido.' });
  if (username && username.toLowerCase() !== authUser.toLowerCase()) {
    return res.status(403).json({ error: 'No puedes crear colecciones en otra cuenta.' });
  }
  const effectiveUser = authUser;

  if (!db.savedCollections) db.savedCollections = {};
  if (!Array.isArray(db.savedCollections[effectiveUser])) db.savedCollections[effectiveUser] = [];

  const newCol = {
    id: 'col-' + Date.now(),
    username: effectiveUser,
    name: name.trim(),
    description: (description || '').trim(),
    createdAt: new Date().toISOString()
  };
  db.savedCollections[effectiveUser].push(newCol);
  saveDatabase(db);
  res.json({ success: true, collection: newCol });
});

app.delete('/api/saved/collections/:id', requireAuth, (req, res) => {
  const { id } = req.params;
  const authUser = (req as any).user.username;
  if (!db.savedCollections?.[authUser]) return res.status(404).json({ error: 'Colección no encontrada.' });

  db.savedCollections[authUser] = db.savedCollections[authUser].filter((c) => c.id !== id);
  // Reassign saved posts from deleted collection to default
  if (db.savedPosts?.[authUser]) {
    for (const sp of db.savedPosts[authUser]) {
      if (sp.collectionId === id) sp.collectionId = null;
    }
  }
  saveDatabase(db);
  res.json({ success: true, message: 'Colección eliminada.' });
});

app.get('/api/saved/posts/:username', requireAuth, (req, res) => {
  const { username } = req.params;
  const authUser = (req as any).user.username;
  const isAdmin = (req as any).user.isFounder || (req as any).user.accountType === 'admin';
  if (username.toLowerCase() !== authUser.toLowerCase() && !isAdmin) {
    return res.status(403).json({ error: 'No tienes autorización para ver publicaciones guardadas de otro usuario.' });
  }
  const collectionId = req.query.collectionId as string;
  const saved = (db.savedPosts?.[username] || []).filter((s) => !collectionId || s.collectionId === collectionId);
  const fullPosts = saved
    .map((s) => ({
      ...s,
      post: (db.posts || []).find((p) => Number(p.id) === Number(s.postId))
    }))
    .filter((s) => Boolean(s.post));

  res.json({ success: true, savedPosts: fullPosts });
});

app.post('/api/saved/toggle', requireAuth, (req, res) => {
  const authUser = (req as any).user.username;
  const { username, postId, collectionId } = req.body;
  if (!postId) return res.status(400).json({ error: 'Datos incompletos.' });
  if (username && username.toLowerCase() !== authUser.toLowerCase()) {
    return res.status(403).json({ error: 'No puedes guardar publicaciones en nombre de otro usuario.' });
  }
  const effectiveUser = authUser;

  if (!db.savedPosts) db.savedPosts = {};
  if (!Array.isArray(db.savedPosts[effectiveUser])) db.savedPosts[effectiveUser] = [];

  const existingIdx = db.savedPosts[effectiveUser].findIndex((s) => Number(s.postId) === Number(postId));
  let isSaved = false;

  if (existingIdx !== -1) {
    db.savedPosts[effectiveUser].splice(existingIdx, 1);
    isSaved = false;
  } else {
    db.savedPosts[effectiveUser].push({
      id: 'sp-' + Date.now(),
      username: effectiveUser,
      postId: Number(postId),
      collectionId: collectionId || null,
      savedAt: new Date().toISOString()
    });
    isSaved = true;
  }

  saveDatabase(db);
  res.json({ success: true, isSaved });
});

// ==========================================
// 24. DESTACAR Y COMPARTIR PUBLICACIONES
// ==========================================
app.post('/api/posts/:id/pin', requireAuth, requireRole(['admin', 'moderador']), (req, res) => {
  const postId = Number(req.params.id);
  const authUser = (req as any).user.username;

  const post = (db.posts || []).find((p) => Number(p.id) === postId);
  if (!post) return res.status(404).json({ error: 'Publicación no encontrada.' });

  post.isPinned = !post.isPinned;
  post.pinnedBy = post.isPinned ? authUser : undefined;
  post.pinnedAt = post.isPinned ? new Date().toISOString() : undefined;

  appendAuditLog(db, {
    adminUsername: authUser,
    action: post.isPinned ? 'PIN_POST' : 'UNPIN_POST',
    details: `${post.isPinned ? 'Destacó' : 'Quitó de destacados'} la publicación "${post.title || 'Publicación'}"`
  });

  saveDatabase(db);
  res.json({ success: true, isPinned: post.isPinned });
});

app.post('/api/posts/:id/share', requireAuth, (req, res) => {
  const postId = Number(req.params.id);
  const authUser = (req as any).user.username;
  const { username, quoteText, targetForumId } = req.body;
  if (username && username.toLowerCase() !== authUser.toLowerCase()) {
    return res.status(403).json({ error: 'No puedes compartir en nombre de otro usuario.' });
  }
  const effectiveUser = authUser;

  const originalPost = (db.posts || []).find((p) => Number(p.id) === postId);
  if (!originalPost) return res.status(404).json({ error: 'Publicación original no encontrada.' });

  originalPost.shareCount = (originalPost.shareCount || 0) + 1;

  if (!Array.isArray(db.forums)) db.forums = [];
  if (!Array.isArray(db.posts)) db.posts = [];

  const sharedPost = {
    id: Date.now(),
    author: effectiveUser,
    forumId: targetForumId || originalPost.forumId,
    forumName: targetForumId ? (db.forums.find((f) => f.id === targetForumId)?.name || originalPost.forumName) : originalPost.forumName,
    tag: originalPost.tag || 'Compartido',
    title: quoteText ? quoteText.slice(0, 60) : `Compartido de @${originalPost.author}: ${originalPost.title || ''}`,
    content: quoteText || `He compartido esta publicación de @${originalPost.author}`,
    type: 'normal',
    timestamp: new Date().toISOString(),
    likes: 0,
    dislikes: 0,
    comments: [],
    nestedComments: [],
    reactions: {},
    reactionCounts: {},
    originalPostId: originalPost.id,
    originalAuthor: originalPost.author,
    originalTitle: originalPost.title,
    originalContent: originalPost.content,
    promotedProductId: originalPost.promotedProductId
  };

  db.posts.unshift(sharedPost);

  if (originalPost.author && originalPost.author !== effectiveUser) {
    if (!Array.isArray(db.notifications)) db.notifications = [];
    db.notifications.unshift({
      id: 'notif-' + Date.now(),
      recipient: originalPost.author,
      sender: effectiveUser,
      type: 'post_shared',
      category: 'community',
      title: 'Publicación compartida',
      message: `@${effectiveUser} ha compartido tu publicación "${(originalPost.title || 'Publicación').slice(0, 30)}..." en el feed comunitario.`,
      relatedId: String(sharedPost.id),
      date: new Date().toISOString(),
      read: false
    });
  }

  saveDatabase(db);
  res.json({ success: true, sharedPost, originalShareCount: originalPost.shareCount });
});

// ==========================================
// 25. PROVEEDORES AUTORIZADOS (VENDORS API)
// ==========================================
app.get('/api/vendors', (req, res) => {
  res.json({ success: true, vendors: db.vendors || [] });
});

app.get('/api/vendors/status/:username', (req, res) => {
  const { username } = req.params;
  const vendor = (db.vendors || []).find((v) => v?.username?.toLowerCase() === username.toLowerCase());
  res.json({ success: true, vendor: vendor || null });
});

app.post('/api/vendors/apply', requireAuth, (req, res) => {
  const authUser = (req as any).user.username;
  const { username, vendorName, description, productTypes, catalogUrl, contactInfo } = req.body;
  if (!vendorName || !description || !contactInfo) {
    return res.status(400).json({ error: 'Campos requeridos incompletos.' });
  }
  if (username && username.toLowerCase() !== authUser.toLowerCase()) {
    return res.status(403).json({ error: 'No puedes enviar solicitudes en nombre de otro usuario.' });
  }
  const effectiveUser = authUser;

  if (!Array.isArray(db.vendors)) db.vendors = [];
  const existing = db.vendors.find((v) => v?.username?.toLowerCase() === effectiveUser.toLowerCase());

  if (existing && (existing.status === 'aprobado' || existing.status === 'pendiente')) {
    return res.status(400).json({ error: `Ya tienes una solicitud en estado: ${existing.status}.` });
  }

  const newVendorApp = {
    id: 'ven-' + Date.now(),
    username: effectiveUser,
    vendorName: vendorName.trim(),
    description: description.trim(),
    productTypes: Array.isArray(productTypes) ? productTypes : [productTypes].filter(Boolean),
    catalogUrl: catalogUrl ? catalogUrl.trim() : undefined,
    contactInfo: contactInfo.trim(),
    status: 'pendiente',
    createdAt: new Date().toISOString()
  };

  db.vendors.push(newVendorApp);

  // Notify admins
  if (!Array.isArray(db.notifications)) db.notifications = [];
  db.notifications.unshift({
    id: 'notif-' + Date.now(),
    recipient: db.firstRegisteredUser || 'admin',
    sender: effectiveUser,
    type: 'vendor_application',
    category: 'empresas',
    title: 'Nueva solicitud de proveedor',
    message: `@${effectiveUser} ha solicitado convertirse en proveedor oficial (${vendorName}).`,
    relatedId: newVendorApp.id,
    date: new Date().toISOString(),
    read: false
  });

  saveDatabase(db);
  res.json({ success: true, vendor: newVendorApp, message: 'Solicitud enviada para revisión del equipo directivo.' });
});

app.put('/api/vendors/:id/status', requireAuth, requireRole(['admin']), (req, res) => {
  const { id } = req.params;
  const authUser = (req as any).user.username;
  const { status, rejectionReason } = req.body;

  const vendor = (db.vendors || []).find((v) => v.id === id);
  if (!vendor) return res.status(404).json({ error: 'Solicitud de proveedor no encontrada.' });

  vendor.status = status;
  vendor.reviewedBy = authUser;
  vendor.reviewedAt = new Date().toISOString();
  if (rejectionReason) vendor.rejectionReason = rejectionReason;

  // Update profile status
  if (db.allProfiles[vendor.username]) {
    db.allProfiles[vendor.username].isVendorApproved = status === 'aprobado';
    db.allProfiles[vendor.username].vendorName = status === 'aprobado' ? vendor.vendorName : undefined;
  }

  // Audit log
  if (!Array.isArray(db.adminAuditLog)) db.adminAuditLog = [];
  db.adminAuditLog.unshift({
    id: 'audit-' + Date.now(),
    adminUsername: authUser,
    action: 'VENDOR_STATUS_CHANGE',
    targetUser: vendor.username,
    details: `Cambió estado de proveedor a "${status}" para ${vendor.vendorName}${rejectionReason ? ` (${rejectionReason})` : ''}`,
    timestamp: new Date().toISOString()
  });

  // Notify vendor
  if (!Array.isArray(db.notifications)) db.notifications = [];
  db.notifications.unshift({
    id: 'notif-' + Date.now(),
    recipient: vendor.username,
    sender: authUser,
    type: 'vendor_approval',
    category: 'tienda',
    title: status === 'aprobado' ? '¡Solicitud de Proveedor Aprobada!' : 'Actualización de Solicitud de Proveedor',
    message: status === 'aprobado'
      ? `Felicidades, ahora eres proveedor oficial de YM-ki Records como "${vendor.vendorName}". Ya puedes publicar artículos autorizados.`
      : `Tu estado de proveedor ha cambiado a "${status}". ${rejectionReason || ''}`,
    relatedId: vendor.id,
    date: new Date().toISOString(),
    read: false
  });

  saveDatabase(db);
  res.json({ success: true, vendor });
});

// ==========================================
// 26. CUPONES & DESCUENTOS ADMINISTRABLES
// ==========================================
app.get('/api/coupons', (req, res) => {
  res.json({ success: true, coupons: db.discountCoupons || [] });
});

app.post('/api/coupons', requireAuth, requireRole(['admin']), requireDelegation('canManageStore'), (req, res) => {
  const authUser = (req as any).user.username;
  const { code, discountPercent, minPurchaseCoins, maxUses, expiresAt } = req.body;

  const cleanCode = (code || '').trim().toUpperCase();
  if (!cleanCode || !discountPercent || Number(discountPercent) <= 0 || Number(discountPercent) > 100) {
    return res.status(400).json({ error: 'Código y porcentaje de descuento válidos requeridos.' });
  }

  if (!Array.isArray(db.discountCoupons)) db.discountCoupons = [];
  const exists = db.discountCoupons.some((c) => c.code === cleanCode);
  if (exists) return res.status(400).json({ error: 'Ya existe un cupón con este código.' });

  const coupon = {
    id: 'coup-' + Date.now(),
    code: cleanCode,
    discountPercent: Number(discountPercent),
    minPurchaseCoins: Math.max(0, Number(minPurchaseCoins) || 0),
    maxUses: Math.max(1, Number(maxUses) || 100),
    usesCount: 0,
    isActive: true,
    expiresAt: expiresAt || undefined,
    createdBy: authUser,
    createdAt: new Date().toISOString()
  };

  db.discountCoupons.push(coupon);
  appendAuditLog(db, {
    adminUsername: authUser,
    action: 'CREATE_COUPON',
    details: `Creó cupón "${coupon.code}" (-${coupon.discountPercent}%)`
  });
  saveDatabase(db);
  res.json({ success: true, coupon });
});

app.post('/api/coupons/validate', (req, res) => {
  const { code, amount } = req.body;
  const cleanCode = (code || '').trim().toUpperCase();
  const coupon = (db.discountCoupons || []).find((c) => c.code === cleanCode && c.isActive);

  if (!coupon) {
    return res.status(404).json({ error: 'Cupón no válido o inactivo.' });
  }

  if (coupon.expiresAt && new Date(coupon.expiresAt).getTime() < Date.now()) {
    return res.status(400).json({ error: 'El cupón ha expirado.' });
  }

  if (coupon.usesCount >= coupon.maxUses) {
    return res.status(400).json({ error: 'El cupón ha alcanzado su límite de usos.' });
  }

  const purchaseAmount = Number(amount || 0);
  if (purchaseAmount < (coupon.minPurchaseCoins || 0)) {
    return res.status(400).json({ error: `Compra mínima de ${coupon.minPurchaseCoins} Coins requerida para este cupón.` });
  }

  const discountAmount = Math.round((purchaseAmount * coupon.discountPercent) / 100);

  res.json({
    success: true,
    coupon,
    discountPercent: coupon.discountPercent,
    discountAmount,
    finalAmount: Math.max(0, purchaseAmount - discountAmount)
  });
});

// ==========================================
// 27. COMPRAS ATÓMICAS & CONTROL DE STOCK
// ==========================================
app.post('/api/store/buy-atomic', requireAuth, (req, res) => {
  const authUser = (req as any).user.username;
  const { buyerUsername, productId, variantId, quantity, currency, couponCode } = req.body;

  const effectiveBuyer = resolveUsernameKey(db.allProfiles, authUser) || authUser;
  if (buyerUsername && buyerUsername.toLowerCase() !== authUser.toLowerCase()) {
    return res.status(403).json({ error: 'No tienes autorización para realizar compras con la cuenta de otro usuario.' });
  }

  const buyer = db.allProfiles[effectiveBuyer];
  if (!buyer) return res.status(404).json({ error: 'Usuario comprador no encontrado.' });
  if (buyer.isSuspended) {
    return res.status(403).json({ error: 'Tu cuenta está suspendida.' });
  }

  const product = (db.products || []).find((p) => p.id === productId);
  if (!product) return res.status(404).json({ error: 'Producto no encontrado.' });

  let variant: any = null;
  if (variantId) {
    const list = db.productVariants?.[productId] || [];
    variant = list.find((v: any) => v.id === variantId);
    if (!variant) return res.status(404).json({ error: 'Variante de producto no encontrada.' });
  }

  const cleanCouponCode = couponCode ? String(couponCode).trim().toUpperCase() : '';
  const coupon = cleanCouponCode
    ? (db.discountCoupons || []).find((c) => c.code === cleanCouponCode)
    : undefined;
  if (cleanCouponCode && !coupon) {
    return res.status(400).json({ error: 'Cupón no válido o inexistente.' });
  }

  const validation = validatePurchaseRequest({
    product,
    variant,
    quantity: quantity ?? 1,
    currency,
    coupon
  });

  if (!validation.ok || !validation.currency || !validation.totalCost || !validation.quantity) {
    return res.status(400).json({ error: validation.error || 'Datos de compra inválidos.' });
  }

  const qty = validation.quantity;
  const cur = validation.currency;
  const totalCost = validation.totalCost;
  const appliedDiscountPercent = validation.discountPercent || 0;

  // Balance check
  const isBuyerUnlimited = isUnlimitedBalanceProfile(buyer);
  const balance = cur === 'gems' ? (buyer.gems || 0) : (buyer.coins || 0);
  if (balance < totalCost && !isBuyerUnlimited) {
    return res.status(400).json({ error: `Saldo insuficiente. Tienes ${balance} ${cur} y el total es ${totalCost} ${cur}.` });
  }

  if (coupon && appliedDiscountPercent > 0) {
    coupon.usesCount = (coupon.usesCount || 0) + 1;
  }

  if (!isBuyerUnlimited) {
    if (cur === 'gems') {
      buyer.gems = Math.max(0, (buyer.gems || 0) - totalCost);
    } else {
      buyer.coins = Math.max(0, (buyer.coins || 0) - totalCost);
    }
  }
  const balanceAfter = cur === 'gems' ? (buyer.gems || 0) : (buyer.coins || 0);

  if (!Array.isArray(db.inventoryMovements)) db.inventoryMovements = [];
  if (!Array.isArray(db.inventory)) db.inventory = [];
  if (!Array.isArray(db.productPurchases)) db.productPurchases = [];

  if (variant) {
    const prev = variant.stockCount;
    variant.stockCount -= qty;
    db.inventoryMovements.unshift({
      id: 'mov-' + Date.now(),
      productId,
      variantId,
      movementType: 'purchase',
      quantity: qty,
      previousStock: prev,
      newStock: variant.stockCount,
      reason: `Compra de ${effectiveBuyer}`,
      createdAt: new Date().toISOString()
    });
  }
  if (product.stockType === 'fixed') {
    const prev = product.stockCount;
    product.stockCount = Math.max(0, (Number(product.stockCount) || 0) - qty);
    db.inventoryMovements.unshift({
      id: 'mov-' + Date.now(),
      productId,
      movementType: 'purchase',
      quantity: qty,
      previousStock: prev,
      newStock: product.stockCount,
      reason: `Compra de ${effectiveBuyer}`,
      createdAt: new Date().toISOString()
    });
  }

  if (product.isFrame) {
    if (!Array.isArray(buyer.ownedFrames)) buyer.ownedFrames = [];
    if (!buyer.ownedFrames.includes(product.id)) {
      buyer.ownedFrames.push(product.id);
    }
    buyer.selectedFrameId = product.id;
  }

  if (product.isAlbum) {
    if (!Array.isArray(db.userAlbums)) db.userAlbums = [];
    db.userAlbums.unshift({
      id: 'ualbum-' + Date.now(),
      ownerUsername: effectiveBuyer,
      productId: product.id,
      albumName: product.name,
      albumType: product.albumType || 'full',
      coverImage: product.images?.[0] || '',
      associatedArtists: product.associatedArtists || [],
      tracks: product.tracks || [],
      purchasedAt: new Date().toISOString(),
      isPreorder: !!product.isPreorder,
      isOpened: false
    });
  }

  const inventoryItem = {
    id: 'inv-' + Date.now() + '-' + Math.floor(Math.random() * 1000),
    ownerUsername: effectiveBuyer,
    productId: product.id,
    productName: variant ? `${product.name} (${variant.name})` : product.name,
    name: variant ? `${product.name} (${variant.name})` : product.name,
    image: product.images?.[0] || '',
    description: product.description,
    pricePaid: totalCost,
    purchasedAt: new Date().toISOString(),
    category: product.category,
    currencyUsed: cur
  };
  db.inventory.unshift(inventoryItem);

  const purchaseRecord = {
    id: 'pur-' + Date.now(),
    buyerUsername: effectiveBuyer,
    productId,
    variantId,
    productName: inventoryItem.productName,
    quantity: qty,
    currencyUsed: cur,
    totalPaid: totalCost,
    couponCode: appliedDiscountPercent > 0 ? cleanCouponCode : undefined,
    purchasedAt: new Date().toISOString()
  };
  db.productPurchases.unshift(purchaseRecord);

  recordLedger({
    username: effectiveBuyer,
    type: cur === 'gems' ? 'spend_gems' : 'spend_coins',
    currency: cur,
    amount: totalCost,
    balanceAfter,
    reason: `Compra en tienda: ${inventoryItem.productName}`
  });

  saveDatabase(db);
  res.json({
    success: true,
    purchase: purchaseRecord,
    inventoryItem,
    buyerCoins: buyer.coins,
    buyerGems: buyer.gems,
    profile: getSafeProfiles(db, effectiveBuyer)[effectiveBuyer] || buyer,
    remainingStock: variant ? variant.stockCount : product.stockCount
  });
});

app.get('/api/store/purchases/:username', requireAuth, (req, res) => {
  const { username } = req.params;
  const authUser = (req as any).user.username;
  const isAdmin = isAdminOrFounder((req as any).user);
  if (authUser.toLowerCase() !== username.toLowerCase() && !isAdmin) {
    return res.status(403).json({ error: 'No tienes autorización para ver el historial de compras de otro usuario.' });
  }
  const purchases = (db.productPurchases || []).filter((p) => p?.buyerUsername?.toLowerCase() === username.toLowerCase());
  res.json({ success: true, purchases });
});

app.get('/api/store/movements', requireAuth, (req, res) => {
  const user = (req as any).user;
  const isAdmin = isAdminOrFounder(user);
  res.json({ success: true, movements: isAdmin ? (db.inventoryMovements || []) : [] });
});

app.post('/api/products/:id/restock', requireAuth, requireRole(['admin']), requireDelegation('canManageStore'), (req, res) => {
  const { id } = req.params;
  const authUser = (req as any).user.username;
  const { additionalStock, reason } = req.body;
  const qty = validatePositiveInt(additionalStock, 1, 100_000);
  if (qty === null) return res.status(400).json({ error: 'Cantidad inválida para reposición.' });

  if (!Array.isArray(db.products)) db.products = [];
  const prod = db.products.find((p: any) => p.id === id);
  if (!prod) return res.status(404).json({ error: 'Producto no encontrado.' });

  const prevStock = prod.stockCount || 0;
  prod.stockCount = prevStock + qty;

  const mov = {
    id: 'mov-' + Date.now(),
    productId: id,
    movementType: 'restock',
    quantity: qty,
    previousStock: prevStock,
    newStock: prod.stockCount,
    reason: reason || `Reposición de stock por @${authUser}`,
    createdBy: authUser,
    createdAt: new Date().toISOString()
  };
  if (!Array.isArray(db.inventoryMovements)) db.inventoryMovements = [];
  db.inventoryMovements.unshift(mov);

  appendAuditLog(db, {
    adminUsername: authUser,
    action: 'RESTOCK_PRODUCT',
    details: `Repuso +${qty} unidades en "${prod.name}"`
  });

  saveDatabase(db);
  res.json({ success: true, product: prod, movement: mov });
});

app.post('/api/products/:id/variants', requireAuth, requireRole(['admin']), requireDelegation('canManageStore'), (req, res) => {
  const { id } = req.params;
  const authUser = (req as any).user.username;
  const { name, variantType, priceCoins, priceGems, stockCount, sku } = req.body;
  if (!name || !variantType) return res.status(400).json({ error: 'Nombre y tipo de variante requeridos.' });

  if (!db.productVariants) db.productVariants = {};
  if (!Array.isArray(db.productVariants[id])) db.productVariants[id] = [];

  const newVar = {
    id: 'var-' + Date.now(),
    productId: id,
    name: String(name).trim(),
    variantType,
    priceCoins: Math.max(1, Number(priceCoins) || 100),
    priceGems: Math.max(1, Number(priceGems) || 1),
    stockCount: Math.max(0, Number(stockCount) || 10),
    sku: sku || `SKU-${Date.now().toString().slice(-4)}`
  };
  db.productVariants[id].push(newVar);
  appendAuditLog(db, {
    adminUsername: authUser,
    action: 'ADD_PRODUCT_VARIANT',
    details: `Añadió variante "${newVar.name}" al producto ${id}`
  });
  saveDatabase(db);
  res.json({ success: true, variant: newVar, variants: db.productVariants[id] });
});

// ==========================================
// 28. TRANSFERENCIAS ATÓMICAS ENTRE USUARIOS
// ==========================================
app.post('/api/economy/transfer-atomic', requireAuth, (req, res) => {
  const authUser = (req as any).user.username;
  const { sender, recipient, currency, amount, reason } = req.body;
  const transferAmt = validatePositiveInt(amount, 1, 100_000);
  const cur = currency === 'gems' ? 'gems' : 'coins';

  const effectiveSender = resolveUsernameKey(db.allProfiles, authUser) || authUser;
  if (sender && sender.toLowerCase() !== authUser.toLowerCase()) {
    return res.status(403).json({ error: 'No tienes autorización para transferir fondos desde la cuenta de otro usuario.' });
  }

  if (!recipient || transferAmt === null) {
    return res.status(400).json({ error: 'Datos de transferencia incompletos o monto entero inválido.' });
  }

  if (effectiveSender.toLowerCase() === String(recipient).trim().toLowerCase()) {
    return res.status(400).json({ error: 'No puedes transferir fondos a tu propia cuenta.' });
  }

  if (!db.allProfiles) db.allProfiles = {};
  const senderUser = db.allProfiles[effectiveSender];
  if (!senderUser) {
    return res.status(404).json({ error: 'Cuenta de remitente no encontrada.' });
  }
  if (senderUser.isSuspended) {
    return res.status(403).json({ error: 'Tu cuenta se encuentra suspendida y no puede transferir fondos.' });
  }

  const recipientKey = resolveUsernameKey(db.allProfiles, String(recipient).trim());
  const recipientUser = recipientKey ? db.allProfiles[recipientKey] : null;
  if (!recipientUser || !recipientKey) {
    return res.status(404).json({ error: `El usuario destinatario "@${String(recipient).trim()}" no existe en la plataforma.` });
  }

  // Check blocks
  if (!db.blockedUsers) db.blockedUsers = {};
  if ((db.blockedUsers[recipientKey] || []).includes(effectiveSender)) {
    return res.status(403).json({ error: 'No puedes transferir fondos a este usuario.' });
  }

  const isUnlimited = isUnlimitedBalanceProfile(senderUser);
  const senderBalance = cur === 'gems' ? (senderUser.gems || 0) : (senderUser.coins || 0);
  if (senderBalance < transferAmt && !isUnlimited) {
    return res.status(400).json({ error: `Saldo insuficiente. Tienes ${senderBalance} ${cur}.` });
  }

  // Execute debit & credit
  if (!isUnlimited) {
    if (cur === 'gems') {
      senderUser.gems = Math.max(0, (senderUser.gems || 0) - transferAmt);
    } else {
      senderUser.coins = Math.max(0, (senderUser.coins || 0) - transferAmt);
    }
  }
  if (cur === 'gems') {
    recipientUser.gems = (recipientUser.gems || 0) + transferAmt;
  } else {
    recipientUser.coins = (recipientUser.coins || 0) + transferAmt;
  }

  recordLedger({
    username: effectiveSender,
    type: cur === 'gems' ? 'transfer_gems_sent' : 'spend_coins',
    currency: cur,
    amount: transferAmt,
    balanceAfter: cur === 'gems' ? (senderUser.gems || 0) : (senderUser.coins || 0),
    reason: reason || `Transferencia enviada a @${recipientKey}`,
    relatedUser: recipientKey
  });

  recordLedger({
    username: recipientKey,
    type: cur === 'gems' ? 'transfer_gems_received' : 'earn_coins',
    currency: cur,
    amount: transferAmt,
    balanceAfter: cur === 'gems' ? (recipientUser.gems || 0) : (recipientUser.coins || 0),
    reason: reason || `Transferencia recibida de @${effectiveSender}`,
    relatedUser: effectiveSender
  });

  if (!Array.isArray(db.notifications)) db.notifications = [];
  db.notifications.unshift({
    id: 'notif-' + Date.now(),
    recipient: recipientKey,
    sender: effectiveSender,
    type: 'transfer_received',
    category: 'compras',
    title: `¡Has recibido ${transferAmt} ${cur}!`,
    message: `@${effectiveSender} te ha enviado ${transferAmt.toLocaleString()} ${cur}.${reason ? ` Nota: "${String(reason).slice(0, 120)}"` : ''}`,
    relatedId: effectiveSender,
    date: new Date().toISOString(),
    read: false
  });

  saveDatabase(db);
  res.json({
    success: true,
    senderBalanceAfter: cur === 'gems' ? (senderUser.gems || 0) : (senderUser.coins || 0),
    profile: getSafeProfiles(db, effectiveSender)[effectiveSender] || senderUser,
    message: `Has transferido con éxito ${transferAmt.toLocaleString()} ${cur} a @${recipientKey}.`
  });
});

// ==========================================
// 29. PERSISTENCIA DE ECONOMÍA, OUTLET, FOROS, CLUBES, CHATS, PREMIOS, LANZAMIENTOS Y NOTIFICACIONES
// ==========================================

// Daily Coins Reward (Once per UTC day)
app.post('/api/economy/daily-claim', requireAuth, (req, res) => {
  const userKey = resolveUsernameKey(db.allProfiles, (req as any).user.username);
  if (!userKey) return res.status(404).json({ error: 'Perfil no encontrado.' });
  const profile = db.allProfiles[userKey];

  const today = new Date().toISOString().slice(0, 10);
  if (profile.lastDailyClaim === today) {
    return res.status(400).json({ error: 'Ya has reclamado tu recompensa diaria hoy.' });
  }

  profile.coins = (profile.coins || 0) + 150;
  profile.gems = (profile.gems || 0) + 2;
  profile.lastDailyClaim = today;

  recordLedger({ username: userKey, type: 'earn_coins', currency: 'coins', amount: 150, balanceAfter: profile.coins, reason: 'Recompensa diaria' });
  recordLedger({ username: userKey, type: 'earn_gems', currency: 'gems', amount: 2, balanceAfter: profile.gems, reason: 'Recompensa diaria' });

  saveDatabase(db);
  res.json({
    success: true,
    profile: getSafeProfiles(db, userKey)[userKey] || profile,
    message: '¡Has reclamado 150 Coins y 2 Gemas diarias!'
  });
});

// Premium Fan Upgrade (500 Coins)
app.post('/api/economy/upgrade-premium', requireAuth, (req, res) => {
  const userKey = resolveUsernameKey(db.allProfiles, (req as any).user.username);
  if (!userKey) return res.status(404).json({ error: 'Perfil no encontrado.' });
  const profile = db.allProfiles[userKey];

  if (profile.accountType !== 'fan') {
    return res.status(400).json({ error: 'Solo cuentas en modo Fan pueden mejorar a Fan Premium.' });
  }
  const price = 500;
  if (!isUnlimitedBalanceProfile(profile)) {
    if ((profile.coins || 0) < price) {
      return res.status(400).json({ error: 'Coins insuficientes para Fan Premium (Requiere 500 Coins).' });
    }
    profile.coins -= price;
    recordLedger({ username: userKey, type: 'spend_coins', currency: 'coins', amount: price, balanceAfter: profile.coins, reason: 'Mejora a Fan Premium' });
  }
  profile.accountType = 'premium_fan';

  saveDatabase(db);
  res.json({
    success: true,
    profile: getSafeProfiles(db, userKey)[userKey] || profile,
    message: '¡Felicidades! Has mejorado a membresía Fan Premium.'
  });
});

// Outlet Listing & Purchase (Atomic 90% payout / 10% platform fee)
app.post('/api/store/outlet/list', requireAuth, (req, res) => {
  const userKey = resolveUsernameKey(db.allProfiles, (req as any).user.username) || (req as any).user.username;
  const { inventoryItemId, resalePrice, isPhotocard } = req.body;
  const cleanPrice = validatePositiveInt(resalePrice, 1, 10_000_000);
  if (cleanPrice === null) return res.status(400).json({ error: 'Precio de reventa inválido.' });

  if (isPhotocard) {
    const card = (db.userPhotocards || []).find((c: any) => c.id === inventoryItemId && c.ownerUsername?.toLowerCase() === userKey.toLowerCase());
    if (!card) return res.status(404).json({ error: 'Photocard no encontrada en tu colección.' });
    if (card.isListedInOutlet) return res.status(400).json({ error: 'Esta photocard ya está publicada en el Outlet.' });
    card.isListedInOutlet = true;
    card.outletPrice = cleanPrice;
    const outletProd = {
      id: 'outlet-pc-' + card.id,
      name: `Photocard: ${card.name} [Outlet]`,
      description: `Photocard oficial de ${card.artist} (${card.albumName || 'Álbum'}). Rareza: ${card.rarity}. Revendedor: @${userKey}.`,
      images: [card.image],
      tags: ['photocard', 'outlet', 'reventa', String(card.artist || '').toLowerCase()],
      stockType: 'fixed',
      stockCount: 1,
      associatedArtists: [card.artist],
      priceCoins: cleanPrice,
      currencyType: 'coins',
      createdBy: userKey,
      isOutlet: true,
      resellerUsername: userKey,
      originalPhotocardId: card.id,
      createdAt: new Date().toISOString(),
      category: 'merch'
    };
    if (!Array.isArray(db.products)) db.products = [];
    db.products.unshift(outletProd);
    saveDatabase(db);
    return res.json({ success: true, product: outletProd, card });
  }

  const item = (db.inventory || []).find((i: any) => i.id === inventoryItemId && (!i.ownerUsername || i.ownerUsername.toLowerCase() === userKey.toLowerCase()));
  if (!item) return res.status(404).json({ error: 'Artículo no encontrado en tu inventario.' });
  if (item.isListedInOutlet) return res.status(400).json({ error: 'Este artículo ya está publicado en el Outlet.' });

  item.isListedInOutlet = true;
  item.outletPrice = cleanPrice;
  const outletProd = {
    id: 'outlet-' + item.id,
    name: `${item.productName} [Outlet]`,
    description: `Reventa oficial por @${userKey}. ${item.description || ''}`,
    images: [item.image],
    tags: ['outlet', 'segunda-mano', 'reventa'],
    stockType: 'fixed',
    stockCount: 1,
    associatedArtists: [],
    priceCoins: cleanPrice,
    currencyType: 'coins',
    createdBy: userKey,
    isOutlet: true,
    resellerUsername: userKey,
    originalProductId: item.productId,
    originalInventoryItemId: item.id,
    createdAt: new Date().toISOString(),
    category: item.category || 'merch'
  };
  if (!Array.isArray(db.products)) db.products = [];
  db.products.unshift(outletProd);
  saveDatabase(db);
  res.json({ success: true, product: outletProd, inventoryItem: item });
});

app.post('/api/store/outlet/buy', requireAuth, (req, res) => {
  const buyerKey = resolveUsernameKey(db.allProfiles, (req as any).user.username) || (req as any).user.username;
  const { outletProductId } = req.body;
  const prodIndex = (db.products || []).findIndex((p: any) => p.id === outletProductId && p.isOutlet);
  if (prodIndex === -1) return res.status(404).json({ error: 'Producto de Outlet no encontrado o ya vendido.' });

  const prod = db.products[prodIndex];
  const sellerKey = resolveUsernameKey(db.allProfiles, prod.resellerUsername) || prod.resellerUsername;
  if (!sellerKey) return res.status(404).json({ error: 'Vendedor no encontrado.' });
  if (sellerKey.toLowerCase() === buyerKey.toLowerCase()) {
    return res.status(400).json({ error: 'No puedes comprar tu propio producto.' });
  }

  const buyer = db.allProfiles[buyerKey];
  const seller = db.allProfiles[sellerKey];
  if (!buyer || !seller) return res.status(404).json({ error: 'Perfil comprador o vendedor no encontrado.' });

  const price = Math.max(1, Number(prod.priceCoins) || 0);
  const isUnlimited = isUnlimitedBalanceProfile(buyer);
  if (!isUnlimited && (buyer.coins || 0) < price) {
    return res.status(400).json({ error: `Coins insuficientes. Precio: ${price} Coins.` });
  }

  if (!isUnlimited) {
    buyer.coins = Math.max(0, (buyer.coins || 0) - price);
    recordLedger({
      username: buyerKey,
      type: 'spend_coins',
      currency: 'coins',
      amount: price,
      balanceAfter: buyer.coins,
      reason: `Compra en Outlet a @${sellerKey}: ${prod.name}`,
      relatedUser: sellerKey
    });
  }

  const sellerEarnings = Math.floor(price * 0.90);
  const platformFee = price - sellerEarnings;
  seller.coins = (seller.coins || 0) + sellerEarnings;
  recordLedger({
    username: sellerKey,
    type: 'earn_coins',
    currency: 'coins',
    amount: sellerEarnings,
    balanceAfter: seller.coins,
    reason: `Venta en Outlet (90% neto, comisión ${platformFee}): ${prod.name}`,
    relatedUser: buyerKey
  });

  db.products.splice(prodIndex, 1);

  if (prod.originalInventoryItemId) {
    db.inventory = (db.inventory || []).filter((i: any) => i.id !== prod.originalInventoryItemId);
  }
  if (prod.originalPhotocardId) {
    const pc = (db.userPhotocards || []).find((c: any) => c.id === prod.originalPhotocardId);
    if (pc) {
      pc.ownerUsername = buyerKey;
      pc.isListedInOutlet = false;
      delete pc.outletPrice;
    }
  }

  const newInvItem = {
    id: 'inv-' + Date.now(),
    ownerUsername: buyerKey,
    productId: prod.originalProductId || prod.id,
    productName: String(prod.name || '').replace(' [Outlet]', '').replace(' [Segunda Mano / Outlet]', ''),
    image: prod.images?.[0] || '',
    description: prod.description,
    pricePaid: price,
    purchasedAt: new Date().toISOString(),
    category: prod.category || 'merch'
  };
  if (!Array.isArray(db.inventory)) db.inventory = [];
  db.inventory.unshift(newInvItem);

  if (!Array.isArray(db.notifications)) db.notifications = [];
  db.notifications.unshift({
    id: 'notif-outlet-' + Date.now(),
    recipient: sellerKey,
    sender: buyerKey,
    type: 'system',
    title: '¡Venta en Outlet concretada!',
    message: `@${buyerKey} ha adquirido "${prod.name}". Has recibido el 90% (${sellerEarnings.toLocaleString()} Coins).`,
    date: new Date().toISOString(),
    read: false
  });

  saveDatabase(db);
  res.json({
    success: true,
    profile: getSafeProfiles(db, buyerKey)[buyerKey] || buyer,
    inventoryItem: newInvItem,
    sellerEarnings,
    platformFee
  });
});

// Album Unboxing
app.post('/api/albums/:id/open', requireAuth, (req, res) => {
  const userKey = resolveUsernameKey(db.allProfiles, (req as any).user.username) || (req as any).user.username;
  const { id } = req.params;
  if (!Array.isArray(db.userAlbums)) db.userAlbums = [];
  const userAlbum = db.userAlbums.find((a: any) => a.id === id);
  if (!userAlbum) return res.status(404).json({ error: 'Álbum no encontrado.' });
  if (userAlbum.ownerUsername && userAlbum.ownerUsername.toLowerCase() !== userKey.toLowerCase()) {
    return res.status(403).json({ error: 'Este álbum pertenece a otro usuario.' });
  }
  if (userAlbum.isOpened && userAlbum.unboxedPhotocards?.length) {
    return res.json({ success: true, userAlbum, pulledCards: userAlbum.unboxedPhotocards });
  }

  const prod = (db.products || []).find((p: any) => p.id === userAlbum.productId);
  const pool = (prod?.photocardsPool && prod.photocardsPool.length > 0) ? prod.photocardsPool : [
    { id: 'pc-def-1', name: 'Debut Holographic Card', artist: userAlbum.associatedArtists?.[0] || 'YM-ki Artist', image: userAlbum.coverImage || '', rarity: 'rara' }
  ];
  const countToPull = prod?.photocardsPerUnbox || (userAlbum.albumType === 'single' ? 1 : userAlbum.albumType === 'mini' ? 2 : 3);
  const pulledCards: any[] = [];
  for (let i = 0; i < countToPull; i++) {
    const idx = crypto.randomInt(0, pool.length);
    pulledCards.push(pool[idx]);
  }
  if (userAlbum.isPreorder && prod?.preorderBenefitPhotocards?.length) {
    pulledCards.push(...prod.preorderBenefitPhotocards);
  }

  if (!Array.isArray(db.userPhotocards)) db.userPhotocards = [];
  const createdCards = pulledCards.map((pc: any, idx: number) => ({
    id: `upc-${Date.now()}-${idx}`,
    ownerUsername: userKey,
    photocardId: pc.id,
    name: pc.name,
    artist: pc.artist,
    image: pc.image,
    rarity: pc.rarity || 'rara',
    albumName: userAlbum.albumName,
    isPreorderBenefit: !!pc.isPreorderBenefit,
    acquiredAt: new Date().toISOString()
  }));
  db.userPhotocards.unshift(...createdCards);
  userAlbum.isOpened = true;
  userAlbum.unboxedPhotocards = pulledCards;

  saveDatabase(db);
  res.json({ success: true, userAlbum, pulledCards, createdCards });
});

// Forums & Posts Persistent CRUD
app.post('/api/forums', requireAuth, (req, res) => {
  const userKey = resolveUsernameKey(db.allProfiles, (req as any).user.username) || (req as any).user.username;
  const user = (req as any).user;
  const { name, description, banner, avatar, bgType, bgValue, isFandomForum, fanClubId, fandomName } = req.body;
  if (!name || !String(name).trim()) return res.status(400).json({ error: 'El nombre del foro es requerido.' });

  const newForum = {
    id: isFandomForum ? 'f-fandom-' + Date.now() : 'f-' + Date.now(),
    name: String(name).trim(),
    description: String(description || '').trim(),
    banner: banner || '',
    avatar: avatar || '',
    creator: userKey,
    followers: 1,
    members: [userKey],
    isJoined: true,
    bgType: bgType || 'solid',
    bgValue: bgValue || '#0f172a',
    isOfficial: isAdminOrFounder(user),
    isFandomForum: Boolean(isFandomForum),
    fanClubId,
    fandomName,
    createdAt: new Date().toISOString()
  };
  if (!Array.isArray(db.forums)) db.forums = [];
  db.forums.unshift(newForum);
  saveDatabase(db);
  res.json({ success: true, forum: newForum, forums: db.forums });
});

app.put('/api/forums/:id', requireAuth, (req, res) => {
  const user = (req as any).user;
  const forum = (db.forums || []).find((f: any) => f.id === req.params.id);
  if (!forum) return res.status(404).json({ error: 'Foro no encontrado.' });
  if (!isAdminOrFounder(user) && forum.creator?.toLowerCase() !== user.username.toLowerCase()) {
    return res.status(403).json({ error: 'No tienes permiso para editar este foro.' });
  }
  const { name, description, banner, avatar, bgType, bgValue } = req.body;
  if (name !== undefined) forum.name = String(name).trim();
  if (description !== undefined) forum.description = String(description).trim();
  if (banner !== undefined) forum.banner = banner;
  if (avatar !== undefined) forum.avatar = avatar;
  if (bgType !== undefined) forum.bgType = bgType;
  if (bgValue !== undefined) forum.bgValue = bgValue;
  saveDatabase(db);
  res.json({ success: true, forum });
});

app.delete('/api/forums/:id', requireAuth, (req, res) => {
  const user = (req as any).user;
  const forum = (db.forums || []).find((f: any) => f.id === req.params.id);
  if (!forum) return res.status(404).json({ error: 'Foro no encontrado.' });
  if (!hasRole(user, ['admin', 'moderador']) && forum.creator?.toLowerCase() !== user.username.toLowerCase()) {
    return res.status(403).json({ error: 'No tienes permiso para eliminar este foro.' });
  }
  db.forums = (db.forums || []).filter((f: any) => f.id !== req.params.id);
  db.posts = (db.posts || []).filter((p: any) => p.forumId !== req.params.id);
  saveDatabase(db);
  res.json({ success: true });
});

app.post('/api/posts', requireAuth, (req, res) => {
  const userKey = resolveUsernameKey(db.allProfiles, (req as any).user.username) || (req as any).user.username;
  const { forumId, forumName, tag, title, content, image, images, type, pollQuestion, pollOption1, pollOption2, promotedProductId } = req.body;
  if (!content && !title) return res.status(400).json({ error: 'El contenido de la publicación es requerido.' });

  const newPost = {
    id: Date.now(),
    author: userKey,
    forumId: forumId || 'general',
    forumName: forumName || 'Comunidad YM-ki',
    tag: tag || 'General',
    title: String(title || '').trim(),
    content: String(content || '').trim(),
    image: image || undefined,
    images: Array.isArray(images) ? images : undefined,
    type: type || 'normal',
    pollQuestion,
    pollOption1,
    pollOption2,
    pollVotes: type === 'poll' ? { option1: 0, option2: 0 } : undefined,
    pollVoters: type === 'poll' ? [] : undefined,
    promotedProductId,
    timestamp: new Date().toISOString(),
    likes: 0,
    dislikes: 0,
    comments: [],
    nestedComments: [],
    reactions: {},
    reactionCounts: {}
  };
  if (!Array.isArray(db.posts)) db.posts = [];
  db.posts.unshift(newPost);

  if (!db.missionProgress) db.missionProgress = {};
  if (!db.missionProgress[userKey]) db.missionProgress[userKey] = {};
  db.missionProgress[userKey].publish_posts = (db.missionProgress[userKey].publish_posts || 0) + 1;

  saveDatabase(db);
  res.json({ success: true, post: newPost });
});

app.delete('/api/posts/:id', requireAuth, (req, res) => {
  const postId = Number(req.params.id);
  const user = (req as any).user;
  const idx = (db.posts || []).findIndex((p: any) => Number(p.id) === postId);
  if (idx === -1) return res.status(404).json({ error: 'Publicación no encontrada.' });
  const post = db.posts[idx];
  if (!hasRole(user, ['admin', 'moderador']) && post.author?.toLowerCase() !== user.username.toLowerCase()) {
    return res.status(403).json({ error: 'Solo el autor, moderadores o administradores pueden eliminar esta publicación.' });
  }
  db.posts.splice(idx, 1);
  if (hasRole(user, ['admin', 'moderador']) && post.author?.toLowerCase() !== user.username.toLowerCase()) {
    appendAuditLog(db, {
      adminUsername: user.username,
      action: 'DELETE_POST',
      targetUser: post.author,
      details: `Eliminó publicación "${post.title || post.id}" de @${post.author}`
    });
  }
  saveDatabase(db);
  res.json({ success: true });
});

// Direct & Group Chat Persistence
app.post('/api/chats/direct', requireAuth, (req, res) => {
  const senderKey = resolveUsernameKey(db.allProfiles, (req as any).user.username) || (req as any).user.username;
  const { toUsername, text, isFanMessage, gift, attachmentUrl, replyToId, replyToText } = req.body;
  if (!toUsername || !text) return res.status(400).json({ error: 'Destinatario y mensaje son requeridos.' });

  const recipientKey = resolveUsernameKey(db.allProfiles, String(toUsername).trim()) || String(toUsername).trim();
  if (!db.blockedUsers) db.blockedUsers = {};
  if ((db.blockedUsers[recipientKey] || []).some((u: string) => u.toLowerCase() === senderKey.toLowerCase())) {
    return res.status(403).json({ error: 'No puedes enviar mensajes a este usuario.' });
  }

  const msg = {
    id: 'm-' + Date.now(),
    from: senderKey,
    to: recipientKey,
    text: String(text),
    timestamp: new Date().toISOString(),
    isFanMessage: Boolean(isFanMessage),
    gift,
    attachmentUrl: attachmentUrl || undefined,
    attachmentType: attachmentUrl ? 'link' : undefined,
    replyToId: replyToId || undefined,
    replyToText: replyToText || undefined,
    status: 'sent'
  };
  if (!db.chats) db.chats = {};
  const key1 = `${senderKey}_${recipientKey}`;
  const key2 = `${recipientKey}_${senderKey}`;
  const existingKey = db.chats[key1] ? key1 : db.chats[key2] ? key2 : key1;
  if (!Array.isArray(db.chats[existingKey])) db.chats[existingKey] = [];
  db.chats[existingKey].push(msg);

  saveDatabase(db);
  res.json({ success: true, messageObj: msg, chatKey: existingKey });
});

app.post('/api/chats/groups', requireAuth, (req, res) => {
  const userKey = resolveUsernameKey(db.allProfiles, (req as any).user.username) || (req as any).user.username;
  const { name, duration, isAdvanced, icon } = req.body;
  if (!name || !String(name).trim()) return res.status(400).json({ error: 'Nombre del grupo requerido.' });

  const newGroup = {
    id: 'grp-' + Date.now(),
    name: String(name).trim(),
    icon,
    creator: userKey,
    admins: [userKey],
    isAdvanced: Boolean(isAdvanced),
    duration: duration === 'temporary' ? 'temporary' : 'permanent',
    members: [userKey],
    categories: isAdvanced
      ? [
          {
            id: 'cat-main',
            name: 'GENERAL',
            subgroups: [
              { id: 'sub-ann', name: 'anuncios-oficiales', type: 'announcement', messages: [] },
              { id: 'sub-gen', name: 'chat-general', type: 'general', messages: [] }
            ]
          }
        ]
      : [],
    messages: [],
    createdAt: new Date().toISOString()
  };
  if (!Array.isArray(db.chatGroups)) db.chatGroups = [];
  db.chatGroups.unshift(newGroup);
  saveDatabase(db);
  res.json({ success: true, group: newGroup });
});

app.post('/api/chats/groups/:groupId/messages', requireAuth, (req, res) => {
  const userKey = resolveUsernameKey(db.allProfiles, (req as any).user.username) || (req as any).user.username;
  const user = (req as any).user;
  const { groupId } = req.params;
  const { text, subgroupId, attachment } = req.body;
  if (!text) return res.status(400).json({ error: 'Texto requerido.' });

  const group = (db.chatGroups || []).find((g: any) => g.id === groupId);
  if (!group) return res.status(404).json({ error: 'Grupo no encontrado.' });
  const isMember =
    isAdminOrFounder(user) ||
    (group.members || []).some((m: string) => m.toLowerCase() === userKey.toLowerCase()) ||
    (group.admins || []).some((a: string) => a.toLowerCase() === userKey.toLowerCase());
  if (!isMember) return res.status(403).json({ error: 'Debes pertenecer a este grupo para enviar mensajes.' });

  const msg = {
    id: 'gmsg-' + Date.now(),
    sender: userKey,
    text: String(text),
    timestamp: new Date().toISOString(),
    attachment
  };

  if (!group.isAdvanced || !subgroupId) {
    if (!Array.isArray(group.messages)) group.messages = [];
    group.messages.push(msg);
  } else {
    let added = false;
    for (const cat of group.categories || []) {
      const sub = (cat.subgroups || []).find((s: any) => s.id === subgroupId);
      if (sub) {
        if (!Array.isArray(sub.messages)) sub.messages = [];
        sub.messages.push(msg);
        added = true;
        break;
      }
    }
    if (!added) return res.status(404).json({ error: 'Canal no encontrado en el grupo.' });
  }
  saveDatabase(db);
  res.json({ success: true, messageObj: msg });
});

// FanClubs Persistent Endpoints
app.post('/api/fanclubs', requireAuth, (req, res) => {
  const userKey = resolveUsernameKey(db.allProfiles, (req as any).user.username) || (req as any).user.username;
  const {
    id,
    name,
    description,
    fandomName,
    avatar,
    banner,
    artists,
    tagColor,
    tagIcon,
    tagIconImg,
    messagePrice,
    exclusiveItems,
    privateForums
  } = req.body || {};
  if (!name || !String(name).trim()) return res.status(400).json({ error: 'Nombre del club requerido.' });

  const requestedId = typeof id === 'string' && id.trim() ? id.trim() : 'fc-' + Date.now();
  const safeId = (db.fanClubs || []).some((c: any) => c.id === requestedId)
    ? `${requestedId}-${Math.floor(Math.random() * 1000)}`
    : requestedId;

  const club = {
    id: safeId,
    name: String(name).trim(),
    description: String(description || '').trim(),
    fandomName: String(fandomName || name).trim(),
    avatar: avatar || '',
    banner: banner || '',
    manager: userKey,
    artists: Array.isArray(artists) ? artists : [],
    members: [userKey],
    privateForums: Array.isArray(privateForums) ? privateForums : [],
    exclusiveItems: Array.isArray(exclusiveItems) ? exclusiveItems : [],
    tagColor: typeof tagColor === 'string' && tagColor.trim() ? tagColor.trim() : '#ec4899',
    tagIcon: typeof tagIcon === 'string' ? tagIcon : '',
    tagIconImg: typeof tagIconImg === 'string' && tagIconImg.trim() ? tagIconImg : undefined,
    messagePrice: Number.isFinite(Number(messagePrice)) ? Math.max(0, Number(messagePrice)) : 20,
    createdAt: new Date().toISOString()
  };
  if (!Array.isArray(db.fanClubs)) db.fanClubs = [];
  db.fanClubs.unshift(club);

  const prof = db.allProfiles[userKey];
  if (prof) {
    if (!prof.fandomDisplayMode) prof.fandomDisplayMode = 'beside_username';
    if (
      Array.isArray(prof.displayedFandomTags) &&
      prof.displayedFandomTags.length > 0 &&
      !prof.displayedFandomTags.includes('__none__') &&
      !prof.displayedFandomTags.includes(club.id)
    ) {
      prof.displayedFandomTags.push(club.id);
    }
  }

  saveDatabase(db);
  res.json({ success: true, fanClub: club, profile: getSafeProfiles(db, userKey)[userKey] });
});

app.put('/api/fanclubs/:id', requireAuth, (req, res) => {
  const actor = (req as any).user;
  const userKey = resolveUsernameKey(db.allProfiles, actor.username) || actor.username;
  const club = (db.fanClubs || []).find((c: any) => c.id === req.params.id);
  if (!club) return res.status(404).json({ error: 'Club de fans no encontrado.' });

  const isPrivileged = Boolean(actor.isFounder || actor.accountType === 'admin');
  const isManager = typeof club.manager === 'string' && club.manager.toLowerCase() === userKey.toLowerCase();
  const body = req.body || {};

  // Allow members to update exclusiveItems claimedBy when claiming/buying, or manager/admin for club config
  const isMember = Array.isArray(club.members) && club.members.some((m: string) => m.toLowerCase() === userKey.toLowerCase());
  if (!isPrivileged && !isManager && !(isMember && body.exclusiveItems && Object.keys(body).length === 1)) {
    return res.status(403).json({ error: 'No tienes autorización para editar este club de fans.' });
  }

  const editableFields = [
    'name', 'description', 'fandomName', 'avatar', 'banner', 'artists',
    'tagColor', 'tagIcon', 'tagIconImg', 'messagePrice', 'privateForums', 'exclusiveItems', 'members'
  ];
  for (const field of editableFields) {
    if (body[field] !== undefined) {
      (club as any)[field] = body[field];
    }
  }

  saveDatabase(db);
  res.json({ success: true, fanClub: club });
});

app.post('/api/fanclubs/:id/join', requireAuth, (req, res) => {
  const userKey = resolveUsernameKey(db.allProfiles, (req as any).user.username) || (req as any).user.username;
  const club = (db.fanClubs || []).find((c: any) => c.id === req.params.id);
  if (!club) return res.status(404).json({ error: 'Club de fans no encontrado.' });
  if (!Array.isArray(club.members)) club.members = [];
  if (!club.members.some((m: string) => m.toLowerCase() === userKey.toLowerCase())) {
    club.members.push(userKey);
    if (!db.missionProgress) db.missionProgress = {};
    if (!db.missionProgress[userKey]) db.missionProgress[userKey] = {};
    db.missionProgress[userKey].join_fanclub = (db.missionProgress[userKey].join_fanclub || 0) + 1;
  }

  const prof = db.allProfiles[userKey];
  if (prof) {
    if (!prof.fandomDisplayMode) prof.fandomDisplayMode = 'beside_username';
    if (
      Array.isArray(prof.displayedFandomTags) &&
      prof.displayedFandomTags.length > 0 &&
      !prof.displayedFandomTags.includes('__none__') &&
      !prof.displayedFandomTags.includes(club.id)
    ) {
      prof.displayedFandomTags.push(club.id);
    }
  }

  saveDatabase(db);
  res.json({ success: true, fanClub: club, profile: getSafeProfiles(db, userKey)[userKey] });
});

app.post('/api/fanclubs/:id/leave', requireAuth, (req, res) => {
  const userKey = resolveUsernameKey(db.allProfiles, (req as any).user.username) || (req as any).user.username;
  const club = (db.fanClubs || []).find((c: any) => c.id === req.params.id);
  if (!club) return res.status(404).json({ error: 'Club de fans no encontrado.' });
  club.members = (club.members || []).filter((m: string) => m.toLowerCase() !== userKey.toLowerCase());
  const prof = db.allProfiles[userKey];
  if (prof && Array.isArray(prof.displayedFandomTags)) {
    prof.displayedFandomTags = prof.displayedFandomTags.filter((t: string) => t !== club.id);
  }
  saveDatabase(db);
  res.json({ success: true, fanClub: club, profile: getSafeProfiles(db, userKey)[userKey] });
});

// Awards Create & Vote Persistent Endpoints
app.post('/api/awards', requireAuth, requireRole(['admin']), (req, res) => {
  const user = (req as any).user;
  const newAward = {
    ...req.body,
    id: req.body?.id || 'award-' + Date.now(),
    createdBy: user.username,
    createdAt: new Date().toISOString()
  };
  if (!Array.isArray(db.awards)) db.awards = [];
  db.awards.unshift(newAward);
  appendAuditLog(db, {
    adminUsername: user.username,
    action: 'CREATE_AWARD',
    details: `Inauguró premiación "${newAward.title}"`
  });
  saveDatabase(db);
  res.json({ success: true, award: newAward, awards: db.awards });
});

app.post('/api/awards/:eventId/vote', requireAuth, (req, res) => {
  const userKey = resolveUsernameKey(db.allProfiles, (req as any).user.username) || (req as any).user.username;
  const { eventId } = req.params;
  const { categoryId, nomineeId } = req.body;
  const event = (db.awards || []).find((e: any) => e.id === eventId);
  if (!event) return res.status(404).json({ error: 'Premiación no encontrada.' });
  const category = (event.categories || []).find((c: any) => c.id === categoryId);
  if (!category) return res.status(404).json({ error: 'Categoría no encontrada.' });
  const nominee = (category.nominees || []).find((n: any) => n.id === nomineeId);
  if (!nominee) return res.status(404).json({ error: 'Nominado no encontrado.' });

  if (!db.userAwardVotes) db.userAwardVotes = {};
  if (!db.userVotedNominees) db.userVotedNominees = {};
  const voteKey = `${userKey}_${categoryId}`;
  const votesCast = db.userAwardVotes[voteKey] || 0;
  const limit = Number(category.votesLimitPerUser) || 1;
  if (votesCast >= limit) {
    return res.status(400).json({ error: `Has alcanzado el límite de votos para esta categoría (${limit} máx).` });
  }

  nominee.votes = (nominee.votes || 0) + 1;
  db.userAwardVotes[voteKey] = votesCast + 1;
  if (!Array.isArray(db.userVotedNominees[voteKey])) db.userVotedNominees[voteKey] = [];
  db.userVotedNominees[voteKey].push(nominee.name);

  if (!db.missionProgress) db.missionProgress = {};
  if (!db.missionProgress[userKey]) db.missionProgress[userKey] = {};
  db.missionProgress[userKey].award_vote = (db.missionProgress[userKey].award_vote || 0) + 1;

  saveDatabase(db);
  res.json({ success: true, votesCast: db.userAwardVotes[voteKey], nominee });
});

// Releases & Magazines Persistent Endpoints
app.post('/api/releases', requireAuth, (req, res) => {
  const user = (req as any).user;
  if (!isAdminOrFounder(user) && user.accountType !== 'artista') {
    return res.status(403).json({ error: 'Solo administradores o artistas oficiales pueden publicar lanzamientos.' });
  }
  const newRel = {
    ...req.body,
    id: req.body?.id || 'rel-' + Date.now(),
    artist: req.body?.artist || user.username,
    createdAt: new Date().toISOString()
  };
  if (!Array.isArray(db.releases)) db.releases = [];
  db.releases.unshift(newRel);
  saveDatabase(db);
  res.json({ success: true, release: newRel, releases: db.releases });
});

app.post('/api/magazines', requireAuth, (req, res) => {
  const user = (req as any).user;
  if (!isAdminOrFounder(user) && user.accountType !== 'diseñador') {
    return res.status(403).json({ error: 'Solo diseñadores o administradores pueden publicar revistas.' });
  }
  const newMag = {
    ...req.body,
    id: req.body?.id || 'mag-' + Date.now(),
    createdBy: user.username,
    createdAt: new Date().toISOString(),
    likes: 0,
    likedBy: []
  };
  if (!Array.isArray(db.magazines)) db.magazines = [];
  db.magazines.unshift(newMag);
  saveDatabase(db);
  res.json({ success: true, magazine: newMag, magazines: db.magazines });
});

app.delete('/api/magazines/:id', requireAuth, (req, res) => {
  const user = (req as any).user;
  const mag = (db.magazines || []).find((m: any) => m.id === req.params.id);
  if (!mag) return res.status(404).json({ error: 'Revista no encontrada.' });
  if (!isAdminOrFounder(user) && mag.createdBy?.toLowerCase() !== user.username.toLowerCase()) {
    return res.status(403).json({ error: 'No tienes permiso para eliminar esta revista.' });
  }
  db.magazines = (db.magazines || []).filter((m: any) => m.id !== req.params.id);
  saveDatabase(db);
  res.json({ success: true });
});

// Notifications Read & Delete Persistent Endpoints
app.put('/api/notifications/:id/read', requireAuth, (req, res) => {
  const userKey = (req as any).user.username;
  const notif = (db.notifications || []).find((n: any) => n.id === req.params.id);
  if (!notif) return res.status(404).json({ error: 'Notificación no encontrada.' });
  if (notif.recipient && notif.recipient.toLowerCase() !== userKey.toLowerCase() && !isAdminOrFounder((req as any).user)) {
    return res.status(403).json({ error: 'No autorizado.' });
  }
  notif.read = true;
  saveDatabase(db);
  res.json({ success: true });
});

app.post('/api/notifications/read-all', requireAuth, (req, res) => {
  const userKey = (req as any).user.username;
  for (const n of db.notifications || []) {
    if (!n.recipient || n.recipient.toLowerCase() === userKey.toLowerCase()) {
      n.read = true;
    }
  }
  saveDatabase(db);
  res.json({ success: true });
});

app.delete('/api/notifications/:id', requireAuth, (req, res) => {
  const userKey = (req as any).user.username;
  const notif = (db.notifications || []).find((n: any) => n.id === req.params.id);
  if (!notif) return res.status(404).json({ error: 'Notificación no encontrada.' });
  if (notif.recipient && notif.recipient.toLowerCase() !== userKey.toLowerCase() && !isAdminOrFounder((req as any).user)) {
    return res.status(403).json({ error: 'No autorizado.' });
  }
  db.notifications = (db.notifications || []).filter((n: any) => n.id !== req.params.id);
  saveDatabase(db);
  res.json({ success: true });
});

async function startServer() {
  // Hydrate `db` from Supabase app_state (or auto-seed from data/db.json) BEFORE listening
  const hydration = await hydrateDatabaseFromSupabase(
    db,
    (candidate) => sanitizeDb(candidate),
    (snapshot) => {
      persistLocalSnapshot(snapshot);
    }
  );
  db = hydration.db;
  if (hydration.warning) {
    lastPersistenceWarning = hydration.warning;
  } else if (hydration.source === 'supabase') {
    console.log(`YM-ki persistence: hydrated from Supabase app_state (${Object.keys(db.allProfiles || {}).length} profiles).`);
  } else if (hydration.source === 'seeded-supabase') {
    console.log(`YM-ki persistence: seeded Supabase app_state from local db.json (${Object.keys(db.allProfiles || {}).length} profiles).`);
  }

  // Prevent any unmatched /api/* request or body-parser error from reaching Vite or static HTML fallback
  app.use('/api', (req, res) => {
    return sendApiError(
      res,
      404,
      `Endpoint API no encontrado: ${req.method} ${req.originalUrl}`,
      'API_NOT_FOUND'
    );
  });

  app.use('/api', (err: any, _req: express.Request, res: express.Response, _next: express.NextFunction) => {
    console.error('Unhandled /api error:', err);
    if (!res.headersSent) {
      const statusCode = Number(err?.status || err?.statusCode) || 500;
      const message =
        err?.type === 'entity.parse.failed'
          ? 'Cuerpo JSON inválido en la solicitud.'
          : err?.type === 'entity.too.large'
            ? 'El tamaño de la solicitud excede el límite permitido.'
            : statusCode >= 500
              ? 'Error interno en el servidor.'
              : err?.message || 'Solicitud inválida.';
      return sendApiError(res, statusCode, message);
    }
  });

  const isDev = process.env.NODE_ENV !== 'production';

  if (isDev) {
    const { createServer: createViteServer } = await import('vite');
    const vite = await createViteServer({
      server: { middlewareMode: true, host: '0.0.0.0', port: PORT, hmr: false },
      appType: 'spa'
    });
    app.use(vite.middlewares);
  } else {
    const distPath = path.resolve(__dirname, 'dist');
    app.use(express.static(distPath));
    app.get('*', (req, res) => {
      if (req.path.startsWith('/api/')) {
        return sendApiError(res, 404, 'Endpoint no encontrado.', 'API_NOT_FOUND');
      }
      const indexFile = path.resolve(distPath, 'index.html');
      if (!fs.existsSync(indexFile)) {
        return res.status(503).send('Aplicación aún no compilada (dist/index.html faltante).');
      }
      res.sendFile(indexFile);
    });
  }

  // Catch-all Express Error Handler
  app.use((err: any, req: express.Request, res: express.Response, _next: express.NextFunction) => {
    console.error('Unhandled server error:', err);
    if (!res.headersSent) {
      const statusCode = Number(err?.status || err?.statusCode) || 500;
      const message = statusCode >= 500 ? 'Error interno en el servidor.' : (err?.message || 'Solicitud inválida.');
      if (req.originalUrl.startsWith('/api/')) {
        return sendApiError(res, statusCode, message);
      }
      res.status(statusCode).json({
        success: false,
        error: message,
        status: statusCode
      });
    }
  });

  process.on('uncaughtException', (err) => {
    console.error('Uncaught server exception:', err);
  });

  process.on('unhandledRejection', (reason, promise) => {
    console.error('Unhandled server rejection at:', promise, 'reason:', reason);
  });

  const flushAndExit = async () => {
    try {
      await flushSupabaseSyncNow();
    } catch {
      // ignore flush error on shutdown
    }
    process.exit(0);
  };
  process.once('SIGTERM', () => { void flushAndExit(); });
  process.once('SIGINT', () => { void flushAndExit(); });

  app.listen(PORT, '0.0.0.0', () => {
    console.log(`YM-ki Web server running on http://0.0.0.0:${PORT}`);
  });
}

startServer().catch((err) => {
  console.error('Failed to start server:', err);
  process.exit(1);
});
