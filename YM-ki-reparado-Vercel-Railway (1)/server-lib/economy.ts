export function isUnlimitedBalanceProfile(profile: any): boolean {
  if (!profile) return false;
  return Boolean(profile.isFounder || profile.accountType === 'admin');
}

export function validatePositiveInt(value: unknown, min = 1, max = 1_000_000): number | null {
  const n = Number(value);
  if (!Number.isFinite(n) || !Number.isInteger(n)) return null;
  if (n < min || n > max) return null;
  return n;
}

export interface PurchaseValidationInput {
  product: any;
  variant?: any;
  quantity: unknown;
  currency?: string;
  coupon?: any;
  nowMs?: number;
}

export interface PurchaseValidationResult {
  ok: boolean;
  error?: string;
  quantity?: number;
  currency?: 'coins' | 'gems';
  unitPrice?: number;
  baseTotal?: number;
  discountPercent?: number;
  totalCost?: number;
}

export function validatePurchaseRequest(input: PurchaseValidationInput): PurchaseValidationResult {
  const { product, variant, quantity, currency, coupon, nowMs = Date.now() } = input;
  const qty = validatePositiveInt(quantity, 1, 99);
  if (qty === null) {
    return { ok: false, error: 'La cantidad debe ser un número entero válido entre 1 y 99.' };
  }

  if (!product) {
    return { ok: false, error: 'Producto no encontrado.' };
  }

  const prodCurrencyType = product.currencyType || 'coins';
  let chosenCur: 'coins' | 'gems';
  if (prodCurrencyType === 'coins') {
    if (currency && currency !== 'coins') {
      return { ok: false, error: 'Este producto solo puede adquirirse con Coins.' };
    }
    chosenCur = 'coins';
  } else if (prodCurrencyType === 'gems') {
    if (currency && currency !== 'gems') {
      return { ok: false, error: 'Este producto solo puede adquirirse con Gemas.' };
    }
    chosenCur = 'gems';
  } else if (prodCurrencyType === 'both') {
    chosenCur = currency === 'gems' ? 'gems' : 'coins';
  } else {
    return { ok: false, error: 'Tipo de moneda del producto inválido.' };
  }

  if (variant) {
    if ((Number(variant.stockCount) || 0) < qty) {
      return {
        ok: false,
        error: `Stock insuficiente en variante "${variant.name}". Quedan ${variant.stockCount}.`
      };
    }
  } else if (product.stockType === 'fixed') {
    if ((Number(product.stockCount) || 0) < qty) {
      return {
        ok: false,
        error: `Stock insuficiente. Quedan ${product.stockCount} unidades disponibles.`
      };
    }
  }

  const rawUnitPrice =
    chosenCur === 'gems'
      ? (variant?.priceGems ?? product.priceGems)
      : (variant?.priceCoins ?? product.priceCoins);
  const unitPrice = Number(rawUnitPrice);

  if (!Number.isFinite(unitPrice) || unitPrice <= 0) {
    return {
      ok: false,
      error: `El precio en ${chosenCur === 'gems' ? 'Gemas' : 'Coins'} de este producto no es válido.`
    };
  }

  const baseTotal = Math.round(unitPrice * qty);
  let totalCost = baseTotal;
  let discountPercent = 0;

  if (coupon) {
    if (chosenCur !== 'coins') {
      return { ok: false, error: 'Los cupones de descuento aplican únicamente a compras con Coins.' };
    }
    if (!coupon.isActive) {
      return { ok: false, error: 'El cupón ingresado no está activo.' };
    }
    if (coupon.expiresAt && new Date(coupon.expiresAt).getTime() <= nowMs) {
      return { ok: false, error: 'El cupón ingresado ha expirado.' };
    }
    if ((coupon.usesCount || 0) >= (coupon.maxUses || 0)) {
      return { ok: false, error: 'El cupón ha alcanzado su límite de usos.' };
    }
    const minPurchase = Number(coupon.minPurchaseCoins) || 0;
    if (baseTotal < minPurchase) {
      return {
        ok: false,
        error: `Compra mínima de ${minPurchase} Coins requerida para aplicar este cupón.`
      };
    }
    discountPercent = Math.min(100, Math.max(0, Number(coupon.discountPercent) || 0));
    totalCost = Math.max(1, Math.round((baseTotal * (100 - discountPercent)) / 100));
  }

  return {
    ok: true,
    quantity: qty,
    currency: chosenCur,
    unitPrice,
    baseTotal,
    discountPercent,
    totalCost
  };
}

export interface AchievementProgressResult {
  eligible: boolean;
  current: number;
  target: number;
}

export function evaluateAchievementEligibility(
  username: string,
  profile: any,
  achievement: any,
  db: any
): AchievementProgressResult {
  const target = Math.max(1, Number(achievement?.targetCount) || 1);
  if (!username || !profile || !achievement) {
    return { eligible: false, current: 0, target };
  }

  const uLower = username.toLowerCase();
  const progressKey = Object.keys(db?.missionProgress || {}).find((k) => k.toLowerCase() === uLower);
  const progressMap = (progressKey && db?.missionProgress?.[progressKey]) || {};

  let current = 0;
  switch (achievement.reqType) {
    case 'first_purchase': {
      const purchases = (db?.productPurchases || []).filter(
        (p: any) => p?.buyerUsername?.toLowerCase() === uLower
      ).length;
      const ownedInv = (db?.inventory || []).filter(
        (i: any) => i?.ownerUsername?.toLowerCase() === uLower
      ).length;
      current = Math.max(purchases, ownedInv);
      break;
    }
    case 'photocards_count': {
      current = (db?.userPhotocards || []).filter(
        (pc: any) => pc?.ownerUsername?.toLowerCase() === uLower
      ).length;
      break;
    }
    case 'votes_count': {
      const voteMapKey = Object.keys(db?.userAwardVotes || {}).find((k) => k.toLowerCase() === uLower);
      const awardVotes = voteMapKey ? Number(db.userAwardVotes[voteMapKey]) || 0 : 0;
      const survivalVotes = (db?.survivals || []).reduce((acc: number, s: any) => {
        const hasVoted = Boolean(s?.votes && Object.keys(s.votes).some((k) => k.toLowerCase() === uLower));
        return acc + (hasVoted ? 1 : 0);
      }, 0);
      current = awardVotes + survivalVotes + (Number(progressMap.award_vote) || 0);
      break;
    }
    case 'audition_completed': {
      const approvedAuditions = (db?.auditions || []).filter(
        (a: any) => a?.applicantUsername?.toLowerCase() === uLower && a?.status === 'aprobada'
      ).length;
      const isRolePromoted = profile.accountType === 'trainee' || profile.accountType === 'artista' ? 1 : 0;
      current = Math.max(approvedAuditions, isRolePromoted);
      break;
    }
    case 'survival_completed': {
      current = (db?.survivals || []).filter((s: any) => {
        const contestant = Array.isArray(s?.contestants)
          ? s.contestants.some((c: any) => c?.username?.toLowerCase() === uLower)
          : false;
        const applicant = Array.isArray(s?.applications)
          ? s.applications.some((a: any) => a?.username?.toLowerCase() === uLower && a?.status === 'accepted')
          : false;
        return contestant || applicant;
      }).length;
      break;
    }
    case 'tracks_listened': {
      current = Number(progressMap.listen_tracks) || 0;
      break;
    }
    case 'community_posts': {
      const userPosts = (db?.posts || []).filter((p: any) => p?.author?.toLowerCase() === uLower).length;
      let userComments = 0;
      for (const p of db?.posts || []) {
        for (const c of p?.comments || []) {
          if (c?.author?.toLowerCase() === uLower) userComments += 1;
        }
      }
      current = Math.max(
        userPosts + userComments,
        (Number(progressMap.publish_posts) || 0) + (Number(progressMap.write_comments) || 0)
      );
      break;
    }
    case 'gem_transfer': {
      const transfers = (db?.economyLedger || []).filter(
        (tx: any) => tx?.username?.toLowerCase() === uLower && tx?.type === 'transfer_gems_sent'
      ).length;
      current = Math.max(transfers, Number(progressMap.gem_transfer) || 0);
      break;
    }
    case 'profile_customized': {
      const hasCustomVisual =
        Boolean(profile.transparentFrame || profile.customTransparentFrame || profile.selectedFrameId) ||
        (profile.ringColor && profile.ringColor !== '#6366f1')
          ? 1
          : 0;
      current = Math.max(hasCustomVisual, Number(progressMap.customize_profile) || 0);
      break;
    }
    case 'collaboration_completed': {
      current = (db?.collaborations || []).filter(
        (c: any) =>
          (c?.status === 'completada' || c?.status === 'aceptada' || c?.status === 'en_desarrollo') &&
          (c?.creatorUsername?.toLowerCase() === uLower ||
            c?.targetUsernameOrCompany?.toLowerCase() === uLower ||
            (Array.isArray(c?.participants) && c.participants.some((p: string) => p?.toLowerCase() === uLower)))
      ).length;
      break;
    }
    default: {
      current = Number(progressMap[achievement.reqType]) || 0;
      break;
    }
  }

  return {
    eligible: current >= target,
    current,
    target
  };
}
