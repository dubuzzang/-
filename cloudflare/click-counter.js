'use strict';

// 짧은 링크 클릭 처리 (Worker 빠른 경로 · 순서 줄(Durable Object) · 로컬 Express 경로가 같이 씀)
// - 방문자는 클릭 저장을 기다리지 않고 바로 이동하고, 클릭 1건은 순서 줄의 대기열에 쌓였다가
//   몇 초마다 links.json · clicks.json에 한꺼번에 반영됨
// - 같은 링크 · 같은 방문자(IP) · 같은 날(KST)은 한 번만 셈 (예전과 같은 규칙)

const CLICK_SOURCES = ['kakao', 'threads', 'instagram', 'naver_app', 'direct', 'other'];
const CODE_PATTERN = /^[A-Za-z0-9_-]{1,64}$/;
const JSON_OPTIONS = { httpMetadata: { contentType: 'application/json; charset=utf-8' } };

function todayKST(now = Date.now()) {
  return new Date(now + 9 * 60 * 60 * 1000).toISOString().slice(0, 10);
}

// Cloudflare가 알려주는 국가 코드(KR 등)를 "대한민국" 같은 이름으로
function countryName(code) {
  const upper = String(code || '').toUpperCase();
  if (!/^[A-Z]{2}$/.test(upper) || upper === 'XX') return '';
  try {
    return new Intl.DisplayNames(['ko'], { type: 'region' }).of(upper) || upper;
  } catch (_error) {
    return upper;
  }
}

// 대기열에 넣는 클릭 1건. 형식이 이상하면 버림 (__proto__ 같은 코드도 여기서 걸러짐)
function cleanClickEvent(event) {
  const code = String((event && event.code) || '');
  const date = String((event && event.date) || '');
  const ip = String((event && event.ip) || '').slice(0, 64);
  const source = CLICK_SOURCES.includes(event && event.source) ? event.source : 'other';
  const country = typeof (event && event.country) === 'string' ? event.country.slice(0, 60) : '';
  if (!CODE_PATTERN.test(code) || code in Object.prototype || !/^\d{4}-\d{2}-\d{2}$/.test(date) || !ip) return null;
  return { code, date, ip, source, country };
}

// 클릭들을 링크 · 중복 확인 기록에 반영. 바뀐 게 있으면 true
function applyClickEvents(links, clicks, events) {
  let changed = false;
  for (const raw of events) {
    const event = cleanClickEvent(raw);
    if (!event || !Object.hasOwn(links, event.code)) continue; // 형식이 이상하거나, 그 사이에 지워진 링크
    const { code, date, ip, source, country } = event;
    if (!Object.hasOwn(clicks, code)) clicks[code] = {};
    if (!Object.hasOwn(clicks[code], date)) clicks[code][date] = {};
    if (Object.hasOwn(clicks[code][date], ip)) continue;
    clicks[code][date][ip] = true;
    const link = links[code];
    link.dailyClicks = link.dailyClicks || {};
    link.dailyClicks[date] = (link.dailyClicks[date] || 0) + 1;
    link.sourceClicks = link.sourceClicks || {};
    link.sourceClicks[source] = (link.sourceClicks[source] || 0) + 1;
    if (country) {
      link.countryClicks = link.countryClicks || {};
      link.countryClicks[country] = (link.countryClicks[country] || 0) + 1;
    }
    changed = true;
  }
  return changed;
}

async function readDocument(bucket, name) {
  const object = await bucket.get(`data/${name}.json`);
  return object ? JSON.parse(await object.text()) : null;
}

// 대기열에 쌓인 클릭을 R2에 한 번 읽고 한 번 써서 반영 (순서 줄 안에서만 부름)
async function flushClickBatch(bucket, events) {
  if (!events.length) return false;
  const [links, clicks] = await Promise.all([readDocument(bucket, 'links'), readDocument(bucket, 'clicks')]);
  if (!links) return false; // links.json을 못 읽으면 아무것도 쓰지 않음 (빈 문서로 덮어쓰지 않게)
  const nextClicks = clicks || {};
  if (!applyClickEvents(links, nextClicks, events)) return false;
  await Promise.all([
    bucket.put('data/links.json', JSON.stringify(links, null, 2), JSON_OPTIONS),
    bucket.put('data/clicks.json', JSON.stringify(nextClicks, null, 2), JSON_OPTIONS)
  ]);
  return true;
}

// 짧은 링크 이동 응답. 링크가 없거나 기간이 끝났으면 예전과 같은 안내 문구, 주소가 이상하면 null(예전 경로가 처리)
function clickResponse(links, code, today) {
  const link = Object.hasOwn(links, code) ? links[code] : null;
  if (!link || typeof link !== 'object') return { status: 404, body: '링크를 찾을 수 없어요' };
  if (link.expiresAt && today > link.expiresAt) {
    return { status: 410, body: '이 링크는 기간이 종료되어 더 이상 사용할 수 없어요.' };
  }
  try {
    return { status: 302, location: new URL(link.url).href };
  } catch (_error) {
    return null;
  }
}

module.exports = {
  CLICK_SOURCES,
  applyClickEvents,
  cleanClickEvent,
  clickResponse,
  countryName,
  flushClickBatch,
  todayKST
};
