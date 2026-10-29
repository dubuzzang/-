'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');
const {
  applyClickEvents,
  cleanClickEvent,
  clickResponse,
  countryName,
  flushClickBatch
} = require('../cloudflare/click-counter');

const today = '2026-10-17';
const yesterday = '2026-10-16';

test('같은 IP가 같은 날 여러 번 눌러도 누를 때마다 세고, 유입 경로·국가별로도 더한다', () => {
  const links = { a: { url: 'https://x.test' }, b: { url: 'https://y.test', dailyClicks: { [today]: 5 } } };
  const changed = applyClickEvents(links, [
    { code: 'a', date: today, ip: '1.1.1.1', source: 'kakao', country: '대한민국' },
    { code: 'a', date: today, ip: '1.1.1.1', source: 'direct', country: '대한민국' },
    { code: 'a', date: today, ip: '2.2.2.2', source: 'direct', country: '' },
    { code: 'a', date: yesterday, ip: '1.1.1.1', source: 'kakao', country: '' },
    { code: 'b', date: today, ip: '1.1.1.1', source: 'spam-source', country: '' },
    { code: 'deleted', date: today, ip: '3.3.3.3', source: 'kakao', country: '' }
  ]);
  assert.equal(changed, true);
  assert.deepEqual(links.a.dailyClicks, { [today]: 3, [yesterday]: 1 }, '같은 IP 1.1.1.1 의 두 번도 둘 다 셈');
  assert.deepEqual(links.a.sourceClicks, { kakao: 2, direct: 2 });
  assert.deepEqual(links.a.countryClicks, { 대한민국: 2 });
  assert.equal(links.b.dailyClicks[today], 6);
  assert.deepEqual(links.b.sourceClicks, { other: 1 }, '모르는 유입 경로는 other로');
  assert.equal(Object.hasOwn(links, 'deleted'), false);
  // 이미 센 IP 가 또 눌러도 다시 셈
  assert.equal(applyClickEvents(links, [{ code: 'a', date: today, ip: '2.2.2.2', source: 'kakao' }]), true);
  assert.equal(links.a.dailyClicks[today], 4);
});

test('__proto__ 같은 코드나 형식이 이상한 클릭은 받지 않고, 기본 속성을 건드리지 않는다', () => {
  for (const bad of [
    { code: '__proto__', date: today, ip: '1' }, { code: '../x', date: today, ip: '1' },
    { code: 'a', date: '2026-13', ip: '1' }, { code: 'a', date: today, ip: '' }, null
  ]) assert.equal(cleanClickEvent(bad), null, JSON.stringify(bad));
  // constructor · toString은 형식은 맞지만 links에 직접 있는 링크가 아니라서 세지 않음
  const links = { a: { url: 'https://x.test' } };
  assert.equal(applyClickEvents(links, [
    { code: '__proto__', date: today, ip: '1.1.1.1' },
    { code: 'constructor', date: today, ip: '1.1.1.1' },
    { code: 'toString', date: today, ip: '1.1.1.1' }
  ]), false);
  assert.equal(({}).dailyClicks, undefined, 'Object.prototype가 오염되지 않음');
  assert.equal(Object.prototype[today], undefined);
  assert.deepEqual(links, { a: { url: 'https://x.test' } });
});

test('이동 응답: 없는 코드·특수 코드는 404, 기간이 끝나면 410, 정상이면 302', () => {
  const links = {
    ok: { url: 'https://www.coupang.com/vp/products/1' },
    old: { url: 'https://x.test', expiresAt: '2026-10-16' },
    lastDay: { url: 'https://x.test/last', expiresAt: today },
    weird: { url: 'not a url' }
  };
  assert.deepEqual(clickResponse(links, 'ok', today), { status: 302, location: 'https://www.coupang.com/vp/products/1' });
  assert.equal(clickResponse(links, 'old', today).status, 410);
  assert.equal(clickResponse(links, 'lastDay', today).status, 302, '만료일 당일까지는 사용 가능');
  for (const code of ['missing', '__proto__', 'constructor', 'hasOwnProperty']) assert.equal(clickResponse(links, code, today).status, 404, code);
  assert.equal(clickResponse(links, 'weird', today), null, '주소가 이상하면 예전 경로가 처리');
});

test('대기열 반영은 R2 links.json 만 한 번 읽고 한 번 쓰며, links.json이 없으면 아무것도 쓰지 않는다', async () => {
  const store = new Map([
    ['data/links.json', JSON.stringify({ a: { url: 'https://x.test', title: 'keep' } })]
  ]);
  const calls = [];
  const bucket = {
    async get(key) { calls.push('get ' + key); return store.has(key) ? { text: async () => store.get(key) } : null; },
    async put(key, value) { calls.push('put ' + key); store.set(key, value); }
  };
  // IP 10개가 50번씩 (같은 IP 가 여러 번 눌러도 다 셈)
  const events = Array.from({ length: 500 }, (_, i) => ({ code: 'a', date: today, ip: `10.0.0.${i % 10}`, source: 'kakao', country: '' }));
  assert.equal(await flushClickBatch(bucket, events), true);
  assert.deepEqual(calls, ['get data/links.json', 'put data/links.json']);
  const links = JSON.parse(store.get('data/links.json'));
  assert.equal(links.a.title, 'keep');
  assert.equal(links.a.dailyClicks[today], 500);
  assert.equal(store.has('data/clicks.json'), false, '중복 확인용 clicks.json 은 이제 안 씀');

  calls.length = 0;
  assert.equal(await flushClickBatch(bucket, []), false);
  assert.deepEqual(calls, []);

  store.delete('data/links.json');
  calls.length = 0;
  assert.equal(await flushClickBatch(bucket, events), false);
  assert.ok(calls.every((call) => call.startsWith('get ')), '빈 문서로 덮어쓰지 않음');
});

test('국가 코드는 한국어 이름으로, 알 수 없는 코드는 빈 값', () => {
  assert.equal(countryName('KR'), '대한민국');
  assert.equal(countryName('xx'), '');
  assert.equal(countryName(''), '');
  assert.equal(countryName('KOR'), '');
});
