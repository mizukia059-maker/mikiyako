import React from 'react';
import { Crown, Mic, CheckCircle2, Sparkles, Shirt, ShieldCheck } from 'lucide-react';
import { UserProfile, FanClub } from '../types';

interface UserBadgesProps {
  user: UserProfile | {
    username: string;
    accountType?: string;
    badgeAdminColor?: string;
    badgeVerifiedColor?: string;
    isFounder?: boolean;
    fandomDisplayMode?: 'beside_username' | 'description';
    displayedFandomTags?: string[];
  };
  fanClubs?: FanClub[];
  className?: string;
  showFandomBadges?: boolean;
  context?: 'beside_username' | 'description' | 'always';
}

export const UserBadges: React.FC<UserBadgesProps> = ({
  user,
  fanClubs = [],
  className = '',
  showFandomBadges = true,
  context = 'beside_username'
}) => {
  const isAdmin = user.accountType === 'admin';
  const isArtist = user.accountType === 'artista';
  const isPremiumFan = user.accountType === 'premium_fan';
  const isDesigner = user.accountType === 'diseñador';
  const isFounder = (user as any).isFounder;

  const adminColor = (user as UserProfile).badgeAdminColor || '#ec4899';
  const verifiedColor = (user as UserProfile).badgeVerifiedColor || '#38bdf8';

  const targetUsername = (user.username || '').trim().toLowerCase();
  const userJoinedClubs = targetUsername
    ? fanClubs.filter(
        (club) =>
          Array.isArray(club.members) &&
          club.members.some((m) => String(m || '').trim().toLowerCase() === targetUsername)
      )
    : [];

  // Filter based on user preferences (treating stale/deleted club IDs gracefully)
  const userDisplayMode = user.fandomDisplayMode || 'beside_username';
  const validClubIds = new Set(fanClubs.map((c) => c.id));
  const activeSelectedTags = (user.displayedFandomTags || []).filter(
    (id) => id === '__none__' || validClubIds.has(id)
  );
  const allowedClubs = userJoinedClubs.filter((club) => {
    if (activeSelectedTags.length === 0) return true;
    if (activeSelectedTags.includes('__none__')) return false;
    return activeSelectedTags.includes(club.id);
  });

  const shouldRenderFandom =
    showFandomBadges &&
    (context === 'always' || context === userDisplayMode);

  return (
    <span className={`inline-flex items-center gap-1 align-middle flex-wrap ${className}`}>
      {isFounder && (
        <span
          title="CEO Fundador Oficial de YM-ki Records"
          className="inline-flex items-center gap-0.5 px-1.5 py-0.5 text-[10px] font-black rounded-full bg-gradient-to-r from-amber-500 to-pink-500 text-slate-950 shadow-sm"
        >
          <ShieldCheck className="w-3 h-3 text-slate-950 inline" /> FOUNDER
        </span>
      )}

      {isAdmin && !isFounder && (
        <>
          <span title="Administrador Oficial">
            <Crown className="w-3.5 h-3.5 inline drop-shadow" style={{ color: adminColor }} />
          </span>
          <span title="Cuenta Verificada">
            <CheckCircle2 className="w-3.5 h-3.5 inline drop-shadow" style={{ color: verifiedColor }} />
          </span>
        </>
      )}

      {isDesigner && (
        <span
          title="Diseñador Oficial YM-ki"
          className="inline-flex items-center gap-0.5 px-1.5 py-0.5 text-[10px] font-bold rounded-full bg-rose-600 text-white shadow-sm"
        >
          <Shirt className="w-2.5 h-2.5" /> Diseñador
        </span>
      )}

      {isArtist && (
        <>
          <span title="Artista Oficial">
            <Mic className="w-3.5 h-3.5 inline drop-shadow" style={{ color: adminColor }} />
          </span>
          <span title="Artista Verificado">
            <CheckCircle2 className="w-3.5 h-3.5 inline drop-shadow" style={{ color: verifiedColor }} />
          </span>
        </>
      )}

      {isPremiumFan && (
        <span
          title="Fan Premium YM-ki"
          className="inline-flex items-center gap-0.5 px-1.5 py-0.5 text-[10px] font-bold rounded-full bg-amber-500 text-slate-950 shadow-sm"
        >
          <Sparkles className="w-2.5 h-2.5" /> VIP
        </span>
      )}

      {shouldRenderFandom &&
        allowedClubs.map((club) => {
          const bg = club.tagColor || '#ec4899';
          const iconSrc = club.tagIconImg || club.tagIcon || '';
          const isImageIcon =
            iconSrc.startsWith('data:') || iconSrc.startsWith('http') || iconSrc.startsWith('/');
          return (
            <span
              key={club.id}
              className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[10px] font-bold text-white shadow-sm transition hover:scale-105"
              style={{ backgroundColor: bg }}
              title={`Fandom Oficial: ${club.fandomName}`}
            >
              {isImageIcon ? (
                <img
                  src={iconSrc}
                  alt={club.fandomName}
                  className="w-4 h-4 rounded-full object-cover inline-block shadow-sm ring-1 ring-white/30"
                />
              ) : iconSrc.trim().length > 0 ? (
                <span className="text-[11px] leading-none">{iconSrc}</span>
              ) : (
                <div
                  className="w-3.5 h-3.5 rounded-full inline-block bg-white/30 border border-white/40"
                  style={{ backgroundColor: `${bg}80` }}
                />
              )}
              <span>{club.fandomName}</span>
            </span>
          );
        })}
    </span>
  );
};
