export interface AuthUserContext {
  username: string;
  accountType: string;
  isFounder?: boolean;
}

export interface AdminDelegationsMap {
  canApproveArtist?: boolean;
  canApproveTrainee?: boolean;
  canManageAuditions?: boolean;
  canManageStore?: boolean;
  canManageSurvival?: boolean;
}

export const DEFAULT_ADMIN_DELEGATIONS: Required<AdminDelegationsMap> = {
  canApproveArtist: true,
  canApproveTrainee: true,
  canManageAuditions: true,
  canManageStore: false,
  canManageSurvival: true
};

export function resolveUsernameKey(
  record: Record<string, any> | undefined,
  candidate: string | undefined
): string | null {
  if (!record || !candidate) return null;
  if (Object.prototype.hasOwnProperty.call(record, candidate)) return candidate;
  const lower = candidate.trim().toLowerCase();
  const found = Object.keys(record).find((k) => k.toLowerCase() === lower);
  return found || null;
}

export function isAdminOrFounder(user: AuthUserContext | null | undefined): boolean {
  if (!user) return false;
  return Boolean(user.isFounder || user.accountType === 'admin');
}

export function hasRole(user: AuthUserContext | null | undefined, allowedRoles: string[]): boolean {
  if (!user || !user.username) return false;
  if (user.isFounder) return true;
  if (allowedRoles.includes('admin') && user.accountType === 'admin') return true;
  return allowedRoles.includes(user.accountType);
}

export function hasDelegatedPermission(
  user: AuthUserContext | null | undefined,
  delegations: Record<string, AdminDelegationsMap> | undefined,
  permissionKey: keyof AdminDelegationsMap,
  firstRegisteredUser?: string
): boolean {
  if (!user || !user.username) return false;
  if (
    user.isFounder ||
    (firstRegisteredUser && firstRegisteredUser.toLowerCase() === user.username.toLowerCase())
  ) {
    return true;
  }
  if (user.accountType !== 'admin') return false;

  const key = resolveUsernameKey(delegations, user.username);
  const perms = key && delegations ? delegations[key] : undefined;
  if (!perms) {
    return DEFAULT_ADMIN_DELEGATIONS[permissionKey];
  }
  if (perms[permissionKey] === undefined) {
    return DEFAULT_ADMIN_DELEGATIONS[permissionKey];
  }
  return Boolean(perms[permissionKey]);
}

export function parseDirectChatParticipants(
  chatKey: string,
  knownUsernames: string[] = []
): [string, string] | null {
  if (!chatKey || typeof chatKey !== 'string') return null;

  // Prefer matching exact known canonical pairs (sorted-joined with '_') so usernames containing '_' still resolve cleanly
  const lowerMap = new Map<string, string>();
  for (const u of knownUsernames) {
    lowerMap.set(u.toLowerCase(), u);
  }

  for (let i = 0; i < chatKey.length; i++) {
    if (chatKey[i] === '_') {
      const left = chatKey.slice(0, i);
      const right = chatKey.slice(i + 1);
      if (left && right && lowerMap.has(left.toLowerCase()) && lowerMap.has(right.toLowerCase())) {
        return [lowerMap.get(left.toLowerCase())!, lowerMap.get(right.toLowerCase())!];
      }
    }
  }

  // Fallback for simple keys without underscore ambiguity
  const parts = chatKey.split('_');
  if (parts.length === 2 && parts[0] && parts[1]) {
    return [parts[0], parts[1]];
  }
  return null;
}

export function filterDirectChatsForUser(
  chats: Record<string, any[]> | undefined,
  requestingUser: string | undefined,
  isPrivileged: boolean,
  knownUsernames: string[] = []
): Record<string, any[]> {
  const result: Record<string, any[]> = {};
  if (!requestingUser || !chats) return result;
  const reqLower = requestingUser.toLowerCase();

  for (const [chatKey, messages] of Object.entries(chats)) {
    if (isPrivileged) {
      result[chatKey] = messages;
      continue;
    }
    const pair = parseDirectChatParticipants(chatKey, knownUsernames);
    if (pair && (pair[0].toLowerCase() === reqLower || pair[1].toLowerCase() === reqLower)) {
      result[chatKey] = messages;
    }
  }
  return result;
}

export function filterChatGroupsForUser(
  chatGroups: any[] | undefined,
  requestingUser: string | undefined,
  isPrivileged: boolean
): any[] {
  if (!Array.isArray(chatGroups)) return [];
  const reqLower = requestingUser?.toLowerCase() || '';

  return chatGroups.map((group) => {
    if (!group || typeof group !== 'object') return group;
    const isMember =
      isPrivileged ||
      (reqLower.length > 0 &&
        ((Array.isArray(group.members) && group.members.some((m: string) => m?.toLowerCase() === reqLower)) ||
          (Array.isArray(group.admins) && group.admins.some((a: string) => a?.toLowerCase() === reqLower)) ||
          (Array.isArray(group.moderators) && group.moderators.some((m: string) => m?.toLowerCase() === reqLower))));

    if (isMember) return group;

    // Redact private channel messages from non-members (keep structure/metadata safe)
    return {
      ...group,
      categories: Array.isArray(group.categories)
        ? group.categories.map((cat: any) => ({
            ...cat,
            subgroups: Array.isArray(cat.subgroups)
              ? cat.subgroups.map((sub: any) => ({
                  ...sub,
                  messages: []
                }))
              : []
          }))
        : []
    };
  });
}

export function isStatusVisibleToUser(
  status: { username: string; visibility?: string; expiresAt?: string | null } | null | undefined,
  requestingUser: string | undefined,
  isPrivileged: boolean,
  followers: Array<{ followerUsername: string; followingUsername: string }> = [],
  nowMs: number = Date.now()
): boolean {
  if (!status || !status.username) return false;
  if (status.expiresAt && new Date(status.expiresAt).getTime() <= nowMs) return false;

  if (isPrivileged) return true;
  if (requestingUser && requestingUser.toLowerCase() === status.username.toLowerCase()) return true;

  const vis = status.visibility || 'public';
  if (vis === 'public') return true;
  if (vis === 'private') return false;
  if (vis === 'followers') {
    if (!requestingUser) return false;
    const reqLower = requestingUser.toLowerCase();
    const ownerLower = status.username.toLowerCase();
    return followers.some(
      (f) => f?.followerUsername?.toLowerCase() === reqLower && f?.followingUsername?.toLowerCase() === ownerLower
    );
  }
  return false;
}

const SELF_PROFILE_ALLOWLIST = new Set([
  'nickname',
  'avatar',
  'banner',
  'description',
  'ringColor',
  'profileBgColor',
  'badgeAdminColor',
  'badgeVerifiedColor',
  'animal',
  'allowMessages',
  'dob',
  'isMerchPrivate',
  'showcaseItemIds',
  'fandom',
  'fandomDisplayMode',
  'displayedFandomTags',
  'buttonTheme',
  'notificationPreferences',
  'calendarPreferences',
  'userBiases',
  'frameScale',
  'frameOffsetX',
  'frameOffsetY',
  'customFrameColor',
  'frameCustomColor',
  'transparentFrame',
  'subscribedEventIds',
  'mutedConversations',
  'userStatus'
]);

const ID_CARD_SAFE_FIELDS = new Set([
  'pseudonym',
  'age',
  'gender',
  'faceclaim',
  'cardColor',
  'stripeColor',
  'specialties',
  'specialty',
  'backPhrase',
  'layoutStyle',
  'customBgUrl'
]);

export function sanitizeSelfProfilePatch(
  existingProfile: any,
  rawUpdates: Record<string, any>,
  isPrivilegedAdmin: boolean
): Record<string, any> {
  const sanitized: Record<string, any> = {};
  if (!rawUpdates || typeof rawUpdates !== 'object') return sanitized;

  for (const [key, value] of Object.entries(rawUpdates)) {
    if (SELF_PROFILE_ALLOWLIST.has(key)) {
      sanitized[key] = value;
      continue;
    }

    if (key === 'idCard' && value && typeof value === 'object') {
      const nextIdCard: Record<string, any> = { ...(existingProfile?.idCard || {}) };
      for (const [cardKey, cardVal] of Object.entries(value)) {
        if (ID_CARD_SAFE_FIELDS.has(cardKey) || isPrivilegedAdmin) {
          nextIdCard[cardKey] = cardVal;
        }
      }
      sanitized.idCard = nextIdCard;
      continue;
    }

    if (key === 'selectedFrameId') {
      if (value === null || value === '') {
        sanitized.selectedFrameId = null;
      } else if (
        isPrivilegedAdmin ||
        (Array.isArray(existingProfile?.ownedFrames) && existingProfile.ownedFrames.includes(value))
      ) {
        sanitized.selectedFrameId = value;
      }
      continue;
    }

    if (key === 'customTransparentFrame') {
      const canUseTransparent =
        isPrivilegedAdmin ||
        existingProfile?.accountType === 'artista' ||
        existingProfile?.accountType === 'premium_fan';
      if (!value || canUseTransparent) {
        sanitized.customTransparentFrame = value;
      }
      continue;
    }

    if (key === 'displayedBadges' && Array.isArray(value)) {
      const ownedBadgeIds = new Set((existingProfile?.customBadges || []).map((b: any) => b.id));
      sanitized.displayedBadges = value.filter((id: string) => ownedBadgeIds.has(id)).slice(0, 5);
      continue;
    }

    // Downgrade self to 'fan' is safe; any role promotion requires admin/server flow
    if (key === 'accountType') {
      if (value === 'fan' && !existingProfile?.isFounder) {
        sanitized.accountType = 'fan';
      } else if (isPrivilegedAdmin) {
        sanitized.accountType = value;
      }
    }
  }

  return sanitized;
}

export function appendAuditLog(
  db: { adminAuditLog?: any[] },
  entry: {
    adminUsername: string;
    action: string;
    targetUser?: string;
    details: string;
  }
): void {
  if (!Array.isArray(db.adminAuditLog)) db.adminAuditLog = [];
  db.adminAuditLog.unshift({
    id: `audit-${Date.now()}-${Math.floor(Math.random() * 1000)}`,
    adminUsername: entry.adminUsername,
    action: entry.action,
    targetUser: entry.targetUser,
    targetUsername: entry.targetUser,
    details: entry.details,
    timestamp: new Date().toISOString()
  });
  if (db.adminAuditLog.length > 1000) {
    db.adminAuditLog.length = 1000;
  }
}
