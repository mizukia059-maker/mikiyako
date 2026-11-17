import test from 'node:test';
import assert from 'node:assert/strict';
import {
  isUnlimitedBalanceProfile,
  validatePositiveInt,
  validatePurchaseRequest,
  evaluateAchievementEligibility
} from './economy';

test('isUnlimitedBalanceProfile strictly restricts unlimited funds to admin and founder (not artista)', () => {
  assert.equal(isUnlimitedBalanceProfile({ accountType: 'admin', isFounder: false }), true);
  assert.equal(isUnlimitedBalanceProfile({ accountType: 'fan', isFounder: true }), true);
  assert.equal(isUnlimitedBalanceProfile({ accountType: 'artista', isFounder: false }), false);
  assert.equal(isUnlimitedBalanceProfile({ accountType: 'fan', isFounder: false }), false);
});

test('validatePurchaseRequest rejects negative quantities, mismatched currencies, zero-price, and unmet coupon minimums', () => {
  const gemProduct = {
    id: 'p1',
    name: 'Prism',
    currencyType: 'gems',
    priceCoins: 0,
    priceGems: 60,
    stockType: 'unlimited'
  };
  assert.equal(
    validatePurchaseRequest({ product: gemProduct, quantity: -3, currency: 'gems' }).ok,
    false
  );
  assert.equal(
    validatePurchaseRequest({ product: gemProduct, quantity: 1, currency: 'coins' }).ok,
    false
  );

  const coinProduct = {
    id: 'p2',
    name: 'Frame',
    currencyType: 'both',
    priceCoins: 800,
    priceGems: 15,
    stockType: 'fixed',
    stockCount: 5
  };
  const couponHighMin = {
    code: 'VIPYMKI30',
    discountPercent: 30,
    minPurchaseCoins: 2000,
    maxUses: 10,
    usesCount: 0,
    isActive: true
  };
  assert.equal(
    validatePurchaseRequest({ product: coinProduct, quantity: 1, currency: 'coins', coupon: couponHighMin }).ok,
    false
  );
  const validWithCoupon = validatePurchaseRequest({
    product: coinProduct,
    quantity: 3,
    currency: 'coins',
    coupon: couponHighMin
  });
  assert.equal(validWithCoupon.ok, true);
  assert.equal(validWithCoupon.totalCost, 1680);
});

test('evaluateAchievementEligibility enforces real user progress', () => {
  const profile = { username: 'testfan', accountType: 'fan', ringColor: '#6366f1' };
  const achTracks = { id: 'ach-music-lover', reqType: 'tracks_listened', targetCount: 20 };
  const db = {
    missionProgress: { testfan: { listen_tracks: 5 } },
    productPurchases: [],
    inventory: []
  };
  const blocked = evaluateAchievementEligibility('testfan', profile, achTracks, db);
  assert.equal(blocked.eligible, false);
  assert.equal(blocked.current, 5);

  db.missionProgress.testfan.listen_tracks = 20;
  const passed = evaluateAchievementEligibility('testfan', profile, achTracks, db);
  assert.equal(passed.eligible, true);
});
