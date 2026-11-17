import test from 'node:test';
import assert from 'node:assert/strict';
import {
  hasRole,
  hasDelegatedPermission,
  filterDirectChatsForUser,
  filterChatGroupsForUser,
  isStatusVisibleToUser,
  sanitizeSelfProfilePatch
} from './rbac';

test('hasRole grants moderator moderation access while blocking non-admins', () => {
  assert.equal(hasRole({ username: 'mod1', accountType: 'moderador' }, ['admin', 'moderador']), true);
  assert.equal(hasRole({ username: 'mod1', accountType: 'moderador' }, ['admin']), false);
  assert.equal(hasRole({ username: 'fan1', accountType: 'fan' }, ['admin', 'moderador']), false);
  assert.equal(hasRole({ username: 'f1', accountType: 'fan', isFounder: true }, ['admin']), true);
});

test('hasDelegatedPermission enforces secondary admin delegation while allowing Founder always', () => {
  const delegations = {
    subadmin: {
      canApproveArtist: false,
      canApproveTrainee: true,
      canManageAuditions: true,
      canManageStore: false,
      canManageSurvival: false
    }
  };
  assert.equal(
    hasDelegatedPermission({ username: 'subadmin', accountType: 'admin' }, delegations, 'canManageStore'),
    false
  );
  assert.equal(
    hasDelegatedPermission({ username: 'subadmin', accountType: 'admin' }, delegations, 'canApproveTrainee'),
    true
  );
  assert.equal(
    hasDelegatedPermission({ username: 'founder', accountType: 'admin', isFounder: true }, delegations, 'canManageStore'),
    true
  );
});

test('filterDirectChatsForUser prevents substring username leaks (test vs testfan)', () => {
  const known = ['test', 'testfan', 'aurora_fan'];
  const chats = {
    aurora_fan_testfan: [{ id: '1', text: 'secret between aurora and testfan' }],
    aurora_fan_test: [{ id: '2', text: 'chat with test' }]
  };
  const visibleToTest = filterDirectChatsForUser(chats, 'test', false, known);
  assert.equal(Object.keys(visibleToTest).length, 1);
  assert.ok(visibleToTest['aurora_fan_test']);
  assert.equal(visibleToTest['aurora_fan_testfan'], undefined);
});

test('filterChatGroupsForUser hides messages of private groups for non-members', () => {
  const groups = [
    {
      id: 'g1',
      name: 'VIP',
      members: ['aurora_fan'],
      admins: [],
      categories: [{ id: 'c1', subgroups: [{ id: 's1', messages: [{ text: 'private' }] }] }]
    }
  ];
  const forOutsider = filterChatGroupsForUser(groups, 'testfan', false);
  assert.equal(forOutsider[0].categories[0].subgroups[0].messages.length, 0);

  const forMember = filterChatGroupsForUser(groups, 'aurora_fan', false);
  assert.equal(forMember[0].categories[0].subgroups[0].messages.length, 1);
});

test('isStatusVisibleToUser respects public, followers, and private visibilities', () => {
  const followers = [{ followerUsername: 'testfan', followingUsername: 'aurora_fan' }];
  assert.equal(isStatusVisibleToUser({ username: 'aurora_fan', visibility: 'private' }, 'testfan', false, followers), false);
  assert.equal(isStatusVisibleToUser({ username: 'aurora_fan', visibility: 'followers' }, 'testfan', false, followers), true);
  assert.equal(isStatusVisibleToUser({ username: 'aurora_fan', visibility: 'followers' }, 'stranger', false, followers), false);
});

test('sanitizeSelfProfilePatch blocks privilege escalation, coin tampering, and unowned badges/frames', () => {
  const existing = {
    username: 'testfan',
    accountType: 'fan',
    isFounder: false,
    coins: 500,
    ownedFrames: ['frame-cyber-neon'],
    customBadges: [{ id: 'b1' }],
    idCard: { pseudonym: 'testfan', rank: 'trainee c' }
  };

  const sanitized = sanitizeSelfProfilePatch(
    existing,
    {
      nickname: 'New Nick',
      accountType: 'admin',
      isFounder: true,
      coins: 999999,
      ownedFrames: ['frame-gold-star'],
      selectedFrameId: 'frame-gold-star',
      displayedBadges: ['b1', 'hacked-badge'],
      idCard: { pseudonym: 'NewId', rank: 'ceo' }
    },
    false
  );

  assert.equal(sanitized.nickname, 'New Nick');
  assert.equal(sanitized.accountType, undefined);
  assert.equal(sanitized.isFounder, undefined);
  assert.equal(sanitized.coins, undefined);
  assert.equal(sanitized.ownedFrames, undefined);
  assert.equal(sanitized.selectedFrameId, undefined);
  assert.deepEqual(sanitized.displayedBadges, ['b1']);
  assert.equal(sanitized.idCard.rank, 'trainee c');
  assert.equal(sanitized.idCard.pseudonym, 'NewId');
});
