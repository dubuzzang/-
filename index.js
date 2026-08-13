const express = require('express');
const fs = require('fs');
const app = express();
const PORT = process.env.PORT || 3000;
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'changeme';

app.use(express.urlencoded({ extended: true }));
app.use(express.json());

const COUPANG_ACCESS_KEY = process.env.COUPANG_ACCESS_KEY || '';
const COUPANG_SECRET_KEY = process.env.COUPANG_SECRET_KEY || '';
const crypto = require('crypto');

const DATA_FILE = '/data/links.json';
const CLICKS_FILE = '/data/clicks.json';
const USERS_FILE = '/data/users.json';
const ACTIVITY_FILE = '/data/activity.json';
const INVITES_FILE = '/data/invites.json';
if (!fs.existsSync(INVITES_FILE)) fs.writeFileSync(INVITES_FILE, JSON.stringify([]));

function loadInvites() { return JSON.parse(fs.readFileSync(INVITES_FILE, 'utf8')); }
function saveInvites(data) { fs.writeFileSync(INVITES_FILE, JSON.stringify(data, null, 2)); }
function generateInviteCode() {
  return crypto.randomBytes(5).toString('hex').toUpperCase();
}
if (!fs.existsSync(ACTIVITY_FILE)) fs.writeFileSync(ACTIVITY_FILE, JSON.stringify([]));

function logActivity(user, action, detail) {
  try {
    const log = JSON.parse(fs.readFileSync(ACTIVITY_FILE, 'utf8'));
    log.unshift({ time: getNowKSTString(), user: user || '(비로그인)', action, detail: detail || '' });
    fs.writeFileSync(ACTIVITY_FILE, JSON.stringify(log.slice(0, 200), null, 2));
  } catch (e) {}
}
function loadActivityLog() {
  try { return JSON.parse(fs.readFileSync(ACTIVITY_FILE, 'utf8')); } catch (e) { return []; }
}

if (!fs.existsSync(DATA_FILE)) fs.writeFileSync(DATA_FILE, JSON.stringify({}));
if (!fs.existsSync(CLICKS_FILE)) fs.writeFileSync(CLICKS_FILE, JSON.stringify({}));

const BASE32_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

function base32Encode(buf) {
  let bits = '';
  for (const b of buf) bits += b.toString(2).padStart(8, '0');
  let out = '';
  for (let i = 0; i + 5 <= bits.length; i += 5) {
    out += BASE32_ALPHABET[parseInt(bits.slice(i, i + 5), 2)];
  }
  const rem = bits.length % 5;
  if (rem) out += BASE32_ALPHABET[parseInt(bits.slice(bits.length - rem).padEnd(5, '0'), 2)];
  return out;
}

function base32Decode(str) {
  const clean = str.toUpperCase().replace(/[^A-Z2-7]/g, '');
  let bits = '';
  for (const c of clean) {
    const idx = BASE32_ALPHABET.indexOf(c);
    if (idx === -1) continue;
    bits += idx.toString(2).padStart(5, '0');
  }
  const bytes = [];
  for (let i = 0; i + 8 <= bits.length; i += 8) bytes.push(parseInt(bits.slice(i, i + 8), 2));
  return Buffer.from(bytes);
}

function generateTotpSecret() {
  return base32Encode(crypto.randomBytes(10));
}

function totpCodeAt(secretBase32, timeStep) {
  const key = base32Decode(secretBase32);
  const buf = Buffer.alloc(8);
  buf.writeBigInt64BE(BigInt(timeStep));
  const hmac = crypto.createHmac('sha1', key).update(buf).digest();
  const offset = hmac[hmac.length - 1] & 0x0f;
  const code = ((hmac[offset] & 0x7f) << 24) | ((hmac[offset + 1] & 0xff) << 16) | ((hmac[offset + 2] & 0xff) << 8) | (hmac[offset + 3] & 0xff);
  return String(code % 1000000).padStart(6, '0');
}

function verifyTotpCode(secretBase32, code) {
  const step = Math.floor(Date.now() / 1000 / 30);
  // 시계가 살짝 안 맞아도 되게, 앞뒤 30초씩 허용
  for (let offset = -1; offset <= 1; offset++) {
    if (totpCodeAt(secretBase32, step + offset) === String(code).trim()) return true;
  }
  return false;
}

// ===== 사용자별 쿠팡 API 키 =====
// - coupangKeyBlob: 2차 비밀번호로만 열리는 버전 → "내 키 보기/수정"에만 사용 (관리자도 2차비번 없인 못 봄)
// - coupangKeyServerBlob: 서버 비밀로 여는 버전 → 검색/자동변환 "사용"에는 매번 비밀번호 입력 없이 자동으로 쓰임
function deriveApiKeyEncKey(secondPassword, salt) {
  // 서버 비밀(ADMIN_PASSWORD)과 사용자의 2차 비밀번호를 함께 섞어서 키를 만듦
  // → 둘 중 하나만 알아서는(서버 파일만 봐도, 2차비번만 알아도) 복호화가 안 됨
  return crypto.scryptSync(secondPassword + ':' + ADMIN_PASSWORD, salt, 32);
}
function deriveServerEncKey(salt) {
  return crypto.scryptSync('coupang-key-server:' + ADMIN_PASSWORD, salt, 32);
}

function encryptWithKey(key, accessKey, secretKey) {
  const salt = key.salt || crypto.randomBytes(16).toString('hex');
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', key.derive(salt), iv);
  const plaintext = JSON.stringify({ accessKey, secretKey });
  const encrypted = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
  const authTag = cipher.getAuthTag();
  return { salt, iv: iv.toString('hex'), authTag: authTag.toString('hex'), data: encrypted.toString('hex') };
}
function decryptWithKey(deriveFn, blob) {
  try {
    const key = deriveFn(blob.salt);
    const decipher = crypto.createDecipheriv('aes-256-gcm', key, Buffer.from(blob.iv, 'hex'));
    decipher.setAuthTag(Buffer.from(blob.authTag, 'hex'));
    const decrypted = Buffer.concat([decipher.update(Buffer.from(blob.data, 'hex')), decipher.final()]);
    return JSON.parse(decrypted.toString('utf8'));
  } catch (e) {
    return null;
  }
}

function encryptCoupangKeys(secondPassword, accessKey, secretKey) {
  return encryptWithKey({ salt: null, derive: (salt) => deriveApiKeyEncKey(secondPassword, salt) }, accessKey, secretKey);
}
function decryptCoupangKeys(secondPassword, blob) {
  return decryptWithKey((salt) => deriveApiKeyEncKey(secondPassword, salt), blob);
}
function encryptCoupangKeysServerSide(accessKey, secretKey) {
  return encryptWithKey({ salt: null, derive: (salt) => deriveServerEncKey(salt) }, accessKey, secretKey);
}
function decryptCoupangKeysServerSide(blob) {
  return decryptWithKey((salt) => deriveServerEncKey(salt), blob);
}

// 이 요청을 보낸 사람이 실제로 어떤 쿠팡 API 키를 써야 하는지 결정
// 관리자 → 서버에 등록된 공용 키 / 일반 사용자 → 등록해둔 개인 키를 비밀번호 입력 없이 자동 사용
function getEffectiveCoupangKeys(req) {
  if (isAdminUser(req)) {
    if (!COUPANG_ACCESS_KEY || !COUPANG_SECRET_KEY) return null;
    return { accessKey: COUPANG_ACCESS_KEY, secretKey: COUPANG_SECRET_KEY, source: 'admin' };
  }
  const username = getCurrentUser(req);
  const users = loadUsers();
  const user = users[username];
  if (!user || !user.coupangKeyServerBlob) return null;
  const result = decryptCoupangKeysServerSide(user.coupangKeyServerBlob);
  if (!result) return null;
  return { accessKey: result.accessKey, secretKey: result.secretKey, source: 'personal' };
}

function hashPassword(password, salt) {
  const s = salt || crypto.randomBytes(16).toString('hex');
  const hash = crypto.scryptSync(password, s, 64).toString('hex');
  return s + ':' + hash;
}
function verifyPassword(password, stored) {
  const [salt, hash] = stored.split(':');
  const check = crypto.scryptSync(password, salt, 64).toString('hex');
  return check === hash;
}

function loadUsers() { return JSON.parse(fs.readFileSync(USERS_FILE, 'utf8')); }
function saveUsers(data) { fs.writeFileSync(USERS_FILE, JSON.stringify(data, null, 2)); }

// 최초 실행 시, 기존 ADMIN_PASSWORD로 로그인 가능한 관리자 계정을 자동으로 만들어둠
if (!fs.existsSync(USERS_FILE)) {
  saveUsers({
    admin: { password: hashPassword(ADMIN_PASSWORD), isAdmin: true, youtubeId: '', email: '', nickname: '', avatarUrl: '', referredBy: '', totpSecret: '', totpEnabled: false, subscriptionType: 'lifetime', subscriptionExpiresAt: '', createdAt: getTodayKST(), adminNote: '' }
  });
}

function loadLinks() { return JSON.parse(fs.readFileSync(DATA_FILE, 'utf8')); }
function saveLinks(data) { fs.writeFileSync(DATA_FILE, JSON.stringify(data, null, 2)); }

// 다중 사용자 기능이 생기기 전에 만들어진 링크는 owner 정보가 없어서,
// 그대로 두면 필터링 때 아무한테도 안 보이게 됨 → 서버 시작 시 자동으로 관리자 소유로 채워줌
(function migrateOwnerlessLinks() {
  try {
    const links = loadLinks();
    let changed = false;
    for (const code in links) {
      if (!links[code].owner) {
        links[code].owner = 'admin';
        changed = true;
      }
    }
    if (changed) saveLinks(links);
  } catch (e) {}
})();

function loadClicks() { return JSON.parse(fs.readFileSync(CLICKS_FILE, 'utf8')); }
function saveClicks(data) { fs.writeFileSync(CLICKS_FILE, JSON.stringify(data, null, 2)); }

function getTodayKST() {
  const now = new Date();
  const kst = new Date(now.getTime() + 9 * 60 * 60 * 1000);
  return kst.toISOString().slice(0, 10);
}

// 활동 로그 등에 쓸, 한국 표준시 기준 "YYYY-MM-DD HH:MM:SS" 문자열
function getNowKSTString() {
  const now = new Date();
  const kst = new Date(now.getTime() + 9 * 60 * 60 * 1000);
  return kst.toISOString().slice(0, 19).replace('T', ' ') + ' (KST)';
}

// 오늘(KST) 기준 N개월 뒤 날짜(YYYY-MM-DD)
function addMonthsToTodayKST(months) {
  const now = new Date();
  const kst = new Date(now.getTime() + 9 * 60 * 60 * 1000);
  kst.setUTCMonth(kst.getUTCMonth() + months);
  return kst.toISOString().slice(0, 10);
}

function addDaysToTodayKST(days) {
  const now = new Date();
  const kst = new Date(now.getTime() + 9 * 60 * 60 * 1000);
  kst.setUTCDate(kst.getUTCDate() + days);
  return kst.toISOString().slice(0, 10);
}

function isInviteExpired(inv) {
  if (!inv.validUntil) return false; // 예전 코드(유효기간 없음)는 계속 유효하게 취급
  return getTodayKST() > inv.validUntil;
}

function getClientIp(req) {
  const forwarded = req.headers['x-forwarded-for'];
  if (forwarded) return forwarded.split(',')[0].trim();
  return req.socket.remoteAddress;
}

// ===== 클릭 지역(국가) 통계 - 무료 IP 위치정보 API + 캐시 =====
const ipCountryCache = {}; // { ip: '대한민국' } 서버 메모리 캐시 (같은 IP 반복 조회 방지)

function isPrivateOrLocalIp(ip) {
  if (!ip) return true;
  const clean = ip.replace('::ffff:', '');
  return clean === '::1' || clean === '127.0.0.1' || /^10\./.test(clean) || /^192\.168\./.test(clean) || /^172\.(1[6-9]|2[0-9]|3[0-1])\./.test(clean);
}

async function lookupCountry(ip) {
  if (isPrivateOrLocalIp(ip)) return null;
  if (ipCountryCache[ip]) return ipCountryCache[ip];
  try {
    const res = await fetch(`http://ip-api.com/json/${encodeURIComponent(ip)}?fields=status,country`);
    const data = await res.json();
    if (data.status === 'success' && data.country) {
      ipCountryCache[ip] = data.country;
      return data.country;
    }
  } catch (e) {}
  return null;
}

async function recordCountryClick(code, ip) {
  const country = await lookupCountry(ip);
  if (!country) return;
  const links = loadLinks();
  const link = links[code];
  if (!link) return;
  if (!link.countryClicks) link.countryClicks = {};
  link.countryClicks[country] = (link.countryClicks[country] || 0) + 1;
  saveLinks(links);
}

function makeSessionToken(username) {
  const sig = crypto.createHmac('sha256', ADMIN_PASSWORD).update(username).digest('hex');
  return Buffer.from(username).toString('base64') + '.' + sig;
}
function parseSessionToken(token) {
  if (!token) return null;
  const parts = token.split('.');
  if (parts.length !== 2) return null;
  const username = Buffer.from(parts[0], 'base64').toString('utf8');
  const expected = crypto.createHmac('sha256', ADMIN_PASSWORD).update(username).digest('hex');
  if (expected !== parts[1]) return null;
  return username;
}
function getCookieValue(req, name) {
  const cookie = req.headers.cookie || '';
  const found = cookie.split(';').map((s) => s.trim()).find((s) => s.indexOf(name + '=') === 0);
  if (!found) return null;
  return decodeURIComponent(found.slice(name.length + 1));
}
function getCurrentUser(req) {
  const username = parseSessionToken(getCookieValue(req, 'radarSession'));
  if (!username) return null;
  const users = loadUsers();
  if (!users[username]) return null;
  return username;
}
function isLoggedIn(req) {
  return !!getCurrentUser(req);
}
function isAdminUser(req) {
  const username = getCurrentUser(req);
  if (!username) return false;
  const users = loadUsers();
  return !!(users[username] && users[username].isAdmin);
}
function getVisibleLinks(req) {
  const currentUser = getCurrentUser(req);
  const isAdmin = isAdminUser(req);
  const allLinks = loadLinks();
  const viewUser = isAdmin ? (req.query && req.query.viewUser) : null;

  const targetUser = viewUser || currentUser;
  const filtered = {};
  for (const code in allLinks) {
    const owner = allLinks[code].owner || 'admin';
    if (owner === targetUser) filtered[code] = allLinks[code];
  }
  return filtered;
}

function escapeHtml(str) {
  return String(str || '').replace(/[&<>"']/g, (c) => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'
  }[c]));
}

// 쿠팡 파트너스 API 인증 서명 만들기
function getSignedDate() {
  const now = new Date();
  const pad = (n) => String(n).padStart(2, '0');
  const YY = String(now.getUTCFullYear()).slice(2);
  const MM = pad(now.getUTCMonth() + 1);
  const DD = pad(now.getUTCDate());
  const HH = pad(now.getUTCHours());
  const mm = pad(now.getUTCMinutes());
  const SS = pad(now.getUTCSeconds());
  return `${YY}${MM}${DD}T${HH}${mm}${SS}Z`;
}

function generateCoupangAuth(method, pathWithQuery, accessKey, secretKey) {
  const [path, query] = pathWithQuery.split('?');
  const signedDate = getSignedDate();
  const message = signedDate + method + path + (query || '');
  const signature = crypto.createHmac('sha256', secretKey).update(message).digest('hex');
  return `CEA algorithm=HmacSHA256, access-key=${accessKey}, signed-date=${signedDate}, signature=${signature}`;
}

// 어떤 형태의 쿠팡 링크든(다른 사람 파트너스 링크 포함) 실제 상품 주소를 먼저 찾아냄
async function resolveToProductUrl(inputUrl) {
  try {
    const res = await fetch(inputUrl, { method: 'GET', redirect: 'follow' });
    const finalUrl = res.url || inputUrl;
    const urlObj = new URL(finalUrl);
    return urlObj.origin + urlObj.pathname;
  } catch (e) {
    return inputUrl;
  }
}

// 쿠팡 상품 페이지 HTML에서 현재 가격을 추출 (실험적 기능)
// 공식 API가 아니라 페이지 내용을 직접 읽어서 숫자를 찾는 방식이라,
// 쿠팡이 페이지 구조를 바꾸면 못 찾을 수 있어요. 그럴 땐 조용히 실패하고 다음날 다시 시도해요.
async function scrapeProductPrice(url) {
  try {
    const res = await fetch(url, {
      method: 'GET',
      headers: { 'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36' }
    });
    const html = await res.text();

    const patterns = [
      /"salePrice"\s*:\s*"?(\d{3,10})"?/,
      /"finalPrice"\s*:\s*"?(\d{3,10})"?/,
      /"price"\s*:\s*"?(\d{3,10})"?/,
      /<meta[^>]+property=["']product:price:amount["'][^>]+content=["'](\d{3,10})["']/,
      /origin-price[^>]*>[^\d]*([\d,]{4,10})/
    ];
    for (const re of patterns) {
      const m = html.match(re);
      if (m) {
        const num = parseInt(m[1].replace(/,/g, ''), 10);
        if (num > 0) return num;
      }
    }
    return null;
  } catch (e) {
    return null;
  }
}

// 매일 한 번, 등록된 모든 링크의 가격을 수집해서 기록
const PRICE_STATE_FILE = '/data/priceCollectionState.json';
async function collectDailyPrices() {
  const today = getTodayKST();
  let state = { lastRun: '' };
  try { state = JSON.parse(fs.readFileSync(PRICE_STATE_FILE, 'utf8')); } catch (e) {}
  if (state.lastRun === today) return; // 오늘 이미 했으면 넘어감

  const links = loadLinks();
  for (const code in links) {
    const link = links[code];
    if (!link.url) continue;
    const price = await scrapeProductPrice(link.url);
    if (price) {
      if (!link.priceHistory) link.priceHistory = {};
      link.priceHistory[today] = price;
    }
    await new Promise((r) => setTimeout(r, 800)); // 너무 빠르게 연속 요청하지 않도록 살짝 텀을 둠
  }
  saveLinks(links);
  fs.writeFileSync(PRICE_STATE_FILE, JSON.stringify({ lastRun: today }));
}

// 서버가 켜져 있는 동안 1시간마다 "오늘 가격 수집 했나?" 확인해서, 안 했으면 실행
setInterval(() => { collectDailyPrices().catch(() => {}); }, 60 * 60 * 1000).unref();
// 서버 시작 5분 뒤에도 한 번 확인 (그날 처음 켜졌을 때를 위해)

// 이용기간이 끝난 사용자(관리자 제외, 평생이용 제외)의 링크를 자동으로 정리
function cleanupExpiredUserLinks() {
  try {
    const users = loadUsers();
    const links = loadLinks();
    let removedCount = 0;
    const affectedUsers = new Set();

    for (const code in links) {
      const owner = links[code].owner;
      const user = users[owner];
      if (user && isSubscriptionExpired(user)) {
        delete links[code];
        removedCount++;
        affectedUsers.add(owner);
      }
    }
    if (removedCount > 0) {
      saveLinks(links);
      logActivity('(시스템)', '이용기간 만료 링크 자동 삭제', [...affectedUsers].join(', ') + ` (${removedCount}개)`);
    }
  } catch (e) {}
}
setTimeout(() => { collectDailyPrices().catch(() => {}); }, 5 * 60 * 1000).unref();

// 1시간마다 만료된 사용자 링크 정리, 서버 시작 1분 뒤에도 한 번 확인
setInterval(cleanupExpiredUserLinks, 60 * 60 * 1000).unref();
setTimeout(cleanupExpiredUserLinks, 60 * 1000).unref();

// 아무 쿠팡 링크나 넣으면 내 파트너스 링크로 변환
async function convertToDeeplink(coupangUrl, accessKey, secretKey) {
  const resolvedUrl = await resolveToProductUrl(coupangUrl);
  const path = '/v2/providers/affiliate_open_api/apis/openapi/v1/deeplink';
  const authorization = generateCoupangAuth('POST', path, accessKey, secretKey);
  const res = await fetch('https://api-gateway.coupang.com' + path, {
    method: 'POST',
    headers: { 'Authorization': authorization, 'Content-Type': 'application/json' },
    body: JSON.stringify({ coupangUrls: [resolvedUrl] })
  });
  const data = await res.json();
  if (data.rCode === '0' && data.data && data.data[0]) {
    return data.data[0].shortenUrl || data.data[0].landingUrl;
  }
  throw new Error(data.rMessage || ('오류 코드: ' + data.rCode));
}

// 상품 이름으로 검색
async function searchCoupangProducts(keyword, accessKey, secretKey) {
  const query = `keyword=${encodeURIComponent(keyword)}&limit=10`;
  const path = '/v2/providers/affiliate_open_api/apis/openapi/products/search';
  const authorization = generateCoupangAuth('GET', `${path}?${query}`, accessKey, secretKey);
  const res = await fetch(`https://api-gateway.coupang.com${path}?${query}`, {
    method: 'GET',
    headers: { 'Authorization': authorization, 'Content-Type': 'application/json' }
  });
  const data = await res.json();
  if (data.rCode === '0' && data.data && data.data.productData) {
    return data.data.productData;
  }
  throw new Error(data.rMessage || ('오류 코드: ' + data.rCode));
}

// 1단계: 누구든 이 주소를 열면 무조건 이 미리보기 화면부터 봐요
function detectSource(req) {
  const ua = (req.headers['user-agent'] || '').toLowerCase();
  if (ua.includes('kakaotalk')) return 'kakao';
  if (ua.includes('threads') || ua.includes('barcelona')) return 'threads';
  if (ua.includes('instagram')) return 'instagram';
  if (ua.includes('naver')) return 'naver_app';
  if (!req.headers.referer) return 'direct';
  return 'other';
}

function isExpired(link) {
  if (!link.expiresAt) return false;
  return getTodayKST() > link.expiresAt;
}

// 관리자는 항상 예외, 평생이용은 만료 없음, 기간제만 날짜 지나면 만료
function isSubscriptionExpired(user) {
  if (!user || user.isAdmin) return false;
  if (!user.subscriptionType || user.subscriptionType === 'lifetime') return false;
  if (!user.subscriptionExpiresAt) return false;
  return getTodayKST() > user.subscriptionExpiresAt;
}

// 네이버 등 일부 이미지 서버는 "다른 사이트에서 직접 불러오기(핫링크)"를 막아둬서,
// 우리 서버가 대신 받아와서 브라우저에 전달해주는 중계 라우트
const ALLOWED_IMAGE_HOSTS = ['phinf.pstatic.net', 'shopping-phinf.pstatic.net', 'shop-phinf.pstatic.net', 'dthumb-phinf.pstatic.net'];
app.get('/img-proxy', async (req, res) => {
  const target = req.query.url;
  if (!target) return res.status(400).send('이미지 주소가 없어요');
  let hostname;
  try { hostname = new URL(target).hostname; } catch (e) { return res.status(400).send('올바른 주소가 아니에요'); }
  if (!ALLOWED_IMAGE_HOSTS.some((h) => hostname === h || hostname.endsWith('.' + h))) {
    return res.status(403).send('허용되지 않은 이미지 서버예요');
  }
  try {
    const upstream = await fetch(target, {
      headers: {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
        'Referer': 'https://shopping.naver.com/'
      }
    });
    if (!upstream.ok) return res.status(upstream.status).send('이미지를 가져오지 못했어요');
    res.setHeader('Content-Type', upstream.headers.get('content-type') || 'image/jpeg');
    res.setHeader('Cache-Control', 'public, max-age=86400');
    const buffer = Buffer.from(await upstream.arrayBuffer());
    res.send(buffer);
  } catch (e) {
    res.status(500).send('이미지를 불러오는 중 오류가 발생했어요');
  }
});

function imgProxyUrl(host, url) {
  try {
    const hostname = new URL(url).hostname;
    if (ALLOWED_IMAGE_HOSTS.some((h) => hostname === h || hostname.endsWith('.' + h))) {
      return `${host}/img-proxy?url=${encodeURIComponent(url)}`;
    }
  } catch (e) {}
  return url;
}

app.get('/r/:code', (req, res) => {
  const code = req.params.code;
  const links = loadLinks();
  if (!links[code]) return res.status(404).send('링크를 찾을 수 없어요');

  const link = links[code];

  if (isExpired(link)) {
    return res.status(410).send('이 링크는 기간이 종료되어 더 이상 사용할 수 없어요.');
  }

  const host = req.protocol + '://' + req.get('host');
  const title = escapeHtml(link.title || code);
  const desc = escapeHtml(link.description || '');
  const image = escapeHtml(link.image ? imgProxyUrl(host, link.image) : '');
  const src = detectSource(req);
  const goUrl = `/r/${encodeURIComponent(code)}/go?src=${encodeURIComponent(src)}`;

  res.send(`
    <!DOCTYPE html>
    <html>
    <head>
      <meta charset="UTF-8">
      <meta name="viewport" content="width=device-width, initial-scale=1">
      <meta property="og:title" content="${title}">
      <meta property="og:description" content="${desc}">
      ${image ? `<meta property="og:image" content="${image}">` : ''}
      <meta property="og:url" content="${host}/r/${code}">
      <title>${title}</title>
      <script>window.location.replace(${JSON.stringify(goUrl)});</script>
      <noscript><meta http-equiv="refresh" content="0;url=${goUrl}"></noscript>
    </head>
    <body></body>
    </html>
  `);
});

// 2단계: 실제 사람만 여기까지 넘어와서 클릭이 카운트되고 쿠팡으로 이동
app.get('/r/:code/go', (req, res) => {
  const code = req.params.code;
  const links = loadLinks();
  if (!links[code]) return res.status(404).send('링크를 찾을 수 없어요');

  const link = links[code];

  if (isExpired(link)) {
    return res.status(410).send('이 링크는 기간이 종료되어 더 이상 사용할 수 없어요.');
  }

  const today = getTodayKST();
  const ip = getClientIp(req);
  const clicks = loadClicks();
  const src = req.query.src || 'other';

  if (!clicks[code]) clicks[code] = {};
  if (!clicks[code][today]) clicks[code][today] = {};

  const alreadyClickedToday = clicks[code][today][ip];

  if (!alreadyClickedToday) {
    if (!link.dailyClicks) link.dailyClicks = {};
    link.dailyClicks[today] = (link.dailyClicks[today] || 0) + 1;
    if (!link.sourceClicks) link.sourceClicks = {};
    link.sourceClicks[src] = (link.sourceClicks[src] || 0) + 1;
    saveLinks(links);
    clicks[code][today][ip] = true;
    saveClicks(clicks);
  }

  res.redirect(link.url);

  // 리다이렉트는 이미 보냈고, 그 이후에 조용히 지역 정보만 비동기로 기록 (사용자 체감 속도에 영향 없음)
  recordCountryClick(code, ip).catch(() => {});
});

// ===== 공통 화이트&핑크 테마 배경 (은은한 구름 블롭 + 코너 잎사귀 장식) =====
const RADAR_BG = `
  <div class="sparkle-blobs">
    <div class="blob blob-1"></div>
    <div class="blob blob-2"></div>
    <div class="blob blob-3"></div>
  </div>
  <svg class="corner-leaf corner-leaf-tr" viewBox="0 0 220 220" xmlns="http://www.w3.org/2000/svg">
    <g fill="none" stroke="#FFC1DE" stroke-width="2.5" opacity="0.55">
      <path d="M210 10 C160 20, 120 60, 90 110 C130 100, 170 80, 210 60"/>
      <path d="M180 15 C150 40, 130 70, 115 105"/>
      <path d="M205 45 C175 55, 150 75, 135 100"/>
    </g>
  </svg>
  <svg class="corner-leaf corner-leaf-bl" viewBox="0 0 220 220" xmlns="http://www.w3.org/2000/svg">
    <g fill="none" stroke="#FFC1DE" stroke-width="2.5" opacity="0.5">
      <path d="M10 210 C20 160, 60 120, 110 90 C100 130, 80 170, 60 210"/>
      <path d="M15 180 C40 150, 70 130, 105 115"/>
      <path d="M45 205 C55 175, 75 150, 100 135"/>
    </g>
  </svg>
`;

// ===== 사용법 설명서 (새 기능을 추가할 때마다 여기에 이어서 기록해요) =====
const FEATURE_GUIDE = [
  {
    title: '🔗 링크 관리 기본',
    items: [
      '새 링크 등록: 코드·쿠팡/토스 링크·제목·설명·이미지·카테고리·만료일·알림단위 입력 후 등록',
      '"자동변환": 아무 쿠팡 링크나 넣으면 내 파트너스 링크로 자동 변환',
      '"🔍 상품 검색해서 채우기": 상품명 검색 → 사진/가격 보고 클릭하면 자동 입력',
      '각 카드에서 "수정하기"/"삭제하기" 가능, 링크 복사 버튼과 QR코드도 제공'
    ]
  },
  {
    title: '📊 통계 · 그래프 · 랭킹',
    items: [
      '오늘 전체/플랫폼별(쿠팡·토스·네이버·올리브영) 클릭수와 일자별 그래프 제공',
      '그래프 밑에 요일 표시, 종합 그래프에는 최고점(핑크)·최저점(라벤더)로 강조',
      '🗓️ 날짜별 방문 합계 조회: 달력에서 하루 또는 기간을 클릭해서 과거 통계 확인',
      '🆚 상품 비교: 두 상품을 골라 오늘/누적 클릭수 비교',
      '20초마다 자동으로 화면이 갱신돼요 (F5 필요 없음)'
    ]
  },
  {
    title: '📁 데이터 관리',
    items: [
      '📊 CSV 다운로드: 전체 링크·클릭 데이터를 엑셀 파일로 저장',
      '카테고리별 필터 버튼으로 상품 목록 걸러보기',
      '만료일을 지정하면 그 날짜가 지난 링크는 자동으로 접속이 막혀요',
      '유입 경로(카카오톡/Threads/인스타/네이버/직접입력) 분석 표시'
    ]
  },
  {
    title: '🔊 사운드 · 음악',
    items: [
      '오른쪽 위 "SOUND ON" 버튼을 눌러야 소리가 활성화돼요 (브라우저 정책)',
      '상품별 누적 클릭수가 알림단위(기본 100)를 넘을 때마다 효과음 + 상품명 음성 안내',
      '10배수(기본 1000)를 넘으면 더 큰 팡파레',
      '유튜브 링크를 내 계정에 등록하면 배경음악처럼 재생 (계정마다 따로 저장, 다른 사람껀 안 들려요)',
      '알림 사운드가 울리는 동안 배경음악 볼륨이 잠깐 줄었다가 자동으로 복귀돼요'
    ]
  }
];

function renderFeatureGuideHtml() {
  return FEATURE_GUIDE.map((section) => `
    <div style="margin-bottom:18px;">
      <div style="font-size:13px; font-weight:800; color:#FF4FA3; margin-bottom:8px;">${section.title}</div>
      <ul style="margin:0; padding-left:18px; font-size:12px; color:#8A6A93; line-height:1.8;">
        ${section.items.map((it) => `<li>${it}</li>`).join('')}
      </ul>
    </div>
  `).join('');
}

const THEME_STYLE = `
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link href="https://fonts.googleapis.com/css2?family=Jua&family=Baloo+2:wght@500;700;800&family=Noto+Sans+KR:wght@400;500;700;800&display=swap" rel="stylesheet">
  <style>
    * { box-sizing: border-box; -webkit-tap-highlight-color: transparent; }
    html { background: #FFF6FA; margin: 0; }
    .cute { font-family: 'Jua', 'Noto Sans KR', sans-serif; letter-spacing: 0.5px; }
    body {
      font-family: 'Noto Sans KR', -apple-system, 'Malgun Gothic', sans-serif;
      background: linear-gradient(160deg, #FFF6FA 0%, #FFEFF6 35%, #FBF3FF 65%, #FFF6FA 100%);
      background-attachment: fixed;
      color: #4A2545;
      margin: 0;
      min-height: 100vh;
      overflow-x: hidden;
      position: relative;
      -webkit-font-smoothing: antialiased;
    }

    .sparkle-blobs { position: fixed; inset: 0; overflow: hidden; pointer-events: none; z-index: 0; }
    .blob {
      position: absolute; border-radius: 50%; filter: blur(60px); opacity: 0.35;
      animation: blobFloat 14s ease-in-out infinite;
    }
    .blob-1 { width: 380px; height: 380px; top: -80px; left: -60px; background: radial-gradient(circle, #FFC8E4, transparent 70%); animation-duration: 16s; }
    .blob-2 { width: 320px; height: 320px; top: 30%; right: -100px; background: radial-gradient(circle, #E3D0FF, transparent 70%); animation-duration: 19s; animation-delay: -4s; }
    .blob-3 { width: 300px; height: 300px; bottom: -80px; left: 20%; background: radial-gradient(circle, #FFE2F0, transparent 70%); animation-duration: 21s; animation-delay: -9s; }
    @keyframes blobFloat {
      0%, 100% { transform: translate(0, 0) scale(1); }
      33% { transform: translate(30px, -25px) scale(1.08); }
      66% { transform: translate(-20px, 20px) scale(0.95); }
    }

    .corner-leaf { position: fixed; width: 220px; height: 220px; pointer-events: none; z-index: 0; }
    .corner-leaf-tr { top: 0; right: 0; }
    .corner-leaf-bl { bottom: 0; left: 0; }
    @media (max-width: 700px) { .corner-leaf { width: 130px; height: 130px; } }

    .cute { text-shadow: 0 1px 0 rgba(255,255,255,0.6); }
    .glass {
      position: relative;
      background: rgba(255,255,255,0.82);
      border: 1px solid rgba(255,111,181,0.28);
      border-radius: 22px;
      box-shadow: 0 10px 30px rgba(255,111,181,0.16), 0 0 0 1px rgba(255,255,255,0.5) inset;
      backdrop-filter: blur(10px);
      z-index: 1;
    }
    .glass > * { position: relative; z-index: 3; }
    input[type="text"], input[type="password"], input[type="email"], input[type="number"], input[type="date"], select {
      width: 100%;
      padding: 11px 14px;
      border-radius: 14px;
      border: 1.5px solid rgba(255,111,181,0.28);
      background: rgba(255,255,255,0.9);
      color: #4A2545;
      margin-bottom: 12px;
      box-sizing: border-box;
      font-size: 14px;
      outline: none;
      font-family: 'Noto Sans KR', sans-serif;
    }
    input::placeholder { color: #C79BC9; }
    input:focus, select:focus { border-color: #FF6FB5; box-shadow: 0 0 0 3px rgba(255,111,181,0.18); }
    button { font-family: inherit; cursor: pointer; }
    .btn-primary {
      background: linear-gradient(135deg, #FF6FB5, #B084F5);
      color: #ffffff;
      border: none;
      padding: 12px 20px;
      border-radius: 999px;
      font-weight: 800;
      letter-spacing: 0.3px;
      box-shadow: 0 6px 18px rgba(255,111,181,0.4);
    }
    .btn-primary:hover { filter: brightness(1.05); }
    .btn-ghost {
      background: #FFFFFF;
      color: #E0399B;
      border: 1.5px solid rgba(255,111,181,0.3);
      padding: 10px 16px;
      border-radius: 999px;
      font-weight: 700;
      box-shadow: 0 2px 8px rgba(255,111,181,0.12);
    }
    .btn-ghost:hover { background: rgba(255,111,181,0.06); }
    a { color: #B84FD6; }
    .mono { font-family: 'Baloo 2', 'Consolas', monospace; }

    .app-shell { display: flex; min-height: 100vh; position: relative; z-index: 1; }
    .sidebar {
      width: 230px; flex-shrink: 0; padding: 28px 18px; display: flex; flex-direction: column;
      position: sticky; top: 0; align-self: flex-start; height: 100vh; overflow-y: auto;
    }
    .sidebar-brand { font-size: 22px; color: #4A2545; margin-bottom: 26px; display: flex; align-items: center; gap: 6px; }
    .sidebar-profile { display: flex; align-items: center; gap: 10px; background: rgba(255,255,255,0.7); border-radius: 16px; padding: 12px; margin-bottom: 20px; }
    .sidebar-avatar { width: 38px; height: 38px; border-radius: 50%; background: rgba(255,111,181,0.18); display: flex; align-items: center; justify-content: center; font-size: 18px; flex-shrink: 0; overflow: hidden; }
    .sidebar-avatar img { width: 100%; height: 100%; object-fit: cover; }
    .sidebar-name { font-size: 13px; font-weight: 700; color: #4A2545; }
    .sidebar-logout { font-size: 11px; color: #B084F5; }
    .sidebar-nav { display: flex; flex-direction: column; gap: 6px; }
    .nav-item {
      display: flex; align-items: center; gap: 10px; text-align: left; width: 100%;
      background: transparent; border: none; color: #8A6A93; font-weight: 600; font-size: 13px;
      padding: 11px 14px; border-radius: 14px;
    }
    .nav-item:hover { background: rgba(255,111,181,0.08); }
    .nav-item.active { background: #FFFFFF; color: #E0399B; box-shadow: 0 2px 10px rgba(255,111,181,0.18); }
    .sidebar-leaf { margin-top: auto; width: 100%; opacity: 0.7; }
    .main-content { flex: 1; min-width: 0; padding: 28px 32px; position: relative; z-index: 1; }

    @media (max-width: 860px) {
      .app-shell { flex-direction: column; }
      .sidebar { width: 100%; height: auto; position: relative; flex-direction: row; flex-wrap: wrap; align-items: center; padding: 16px; gap: 10px 14px; }
      .sidebar-brand { margin-bottom: 0; font-size: 18px; }
      .sidebar-profile { margin-bottom: 0; }
      .sidebar-nav { flex-direction: row; flex-wrap: wrap; flex: 1; }
      .sidebar-leaf { display: none; }
      .main-content { padding: 16px; }
    }
  </style>
`;

app.get('/admin/login', (req, res) => {
  const savedUsername = getCookieValue(req, 'savedUsername') || '';
  const autoLoginPref = getCookieValue(req, 'autoLoginPref') === '1';
  res.send(`
    <!DOCTYPE html>
    <html><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1">${THEME_STYLE}</head>
    <body style="display:flex; justify-content:center; align-items:center; height:100vh;">
      ${RADAR_BG}
      <form method="POST" action="/admin/login" class="glass" style="padding:36px; width:300px;">
        <div style="font-size:12px; color:#E0399B; letter-spacing:2px; margin-bottom:6px;">💗 반짝 로그인</div>
        <h2 class="cute" style="margin:0 0 20px; color:#4A2545; font-weight:normal;">로그인</h2>
        <input type="text" name="username" placeholder="아이디" required autocomplete="username" value="${escapeHtml(savedUsername)}">
        <input type="password" name="password" placeholder="비밀번호" required autocomplete="current-password">
        <label style="font-size:11px; color:#8A6A93; display:flex; align-items:center; gap:6px; margin-bottom:6px;">
          <input type="checkbox" name="saveId" style="width:auto; margin:0;" ${savedUsername ? 'checked' : ''}> 아이디 저장
        </label>
        <label style="font-size:11px; color:#8A6A93; display:flex; align-items:center; gap:6px; margin-bottom:12px;">
          <input type="checkbox" name="autoLogin" style="width:auto; margin:0;" ${autoLoginPref ? 'checked' : ''}> 자동 로그인 (30일 동안 로그인 유지)
        </label>
        <button type="submit" class="btn-primary" style="width:100%; margin-top:6px;">접속하기</button>
        <div style="display:flex; justify-content:space-between; margin-top:14px; font-size:11px;">
          <a href="/admin/signup" style="color:#8A6A93;">회원가입</a>
          <a href="/admin/find-id" style="color:#8A6A93;">아이디 찾기</a>
          <a href="/admin/reset-password" style="color:#8A6A93;">비밀번호 찾기</a>
        </div>
      </form>
    </body></html>
  `);
});

function makePendingToken(username) {
  const sig = crypto.createHmac('sha256', ADMIN_PASSWORD).update('PENDING:' + username).digest('hex');
  return Buffer.from(username).toString('base64') + '.' + sig;
}
function parsePendingToken(token) {
  if (!token) return null;
  const parts = token.split('.');
  if (parts.length !== 2) return null;
  const username = Buffer.from(parts[0], 'base64').toString('utf8');
  const expected = crypto.createHmac('sha256', ADMIN_PASSWORD).update('PENDING:' + username).digest('hex');
  if (expected !== parts[1]) return null;
  return username;
}

function applyLoginCookies(res, username, saveId, autoLogin) {
  const sessionMaxAge = autoLogin ? 60 * 60 * 24 * 30 : 60 * 60 * 24; // 자동로그인 체크시 30일, 아니면 1일
  const token = makeSessionToken(username);
  const cookies = [`radarSession=${encodeURIComponent(token)}; HttpOnly; Path=/; SameSite=Lax; Max-Age=${sessionMaxAge}`];
  if (saveId) {
    cookies.push(`savedUsername=${encodeURIComponent(username)}; Path=/; SameSite=Lax; Max-Age=${60 * 60 * 24 * 90}`);
  } else {
    cookies.push('savedUsername=; Path=/; SameSite=Lax; Max-Age=0');
  }
  // 자동로그인 체크박스 자체를 기억해둬서, 다음에 로그인 화면 열 때 미리 체크되어 있게 함
  // (이걸 체크하는 걸 깜빡해서 "자동로그인이 안 된다"고 느끼는 경우가 많아서 넣음)
  if (autoLogin) {
    cookies.push(`autoLoginPref=1; Path=/; SameSite=Lax; Max-Age=${60 * 60 * 24 * 90}`);
  } else {
    cookies.push('autoLoginPref=; Path=/; SameSite=Lax; Max-Age=0');
  }
  res.setHeader('Set-Cookie', cookies);
}

app.post('/admin/login', (req, res) => {
  const { username, password, saveId, autoLogin } = req.body;
  const users = loadUsers();
  const user = users[(username || '').trim()];
  if (user && verifyPassword(password || '', user.password)) {
    if (user.totpEnabled && user.totpSecret) {
      const pending = makePendingToken(username.trim());
      return res.send(`
        <!DOCTYPE html>
        <html><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1">${THEME_STYLE}</head>
        <body style="display:flex; justify-content:center; align-items:center; height:100vh;">
          ${RADAR_BG}
          <form method="POST" action="/admin/login/verify-2fa" class="glass" style="padding:36px; width:300px;">
            <div style="font-size:12px; color:#E0399B; letter-spacing:2px; margin-bottom:6px;">🛡️ 2FA</div>
            <h2 class="cute" style="margin:0 0 20px; color:#4A2545; font-weight:normal;">인증 코드 입력</h2>
            <input type="hidden" name="pending" value="${escapeHtml(pending)}">
            <input type="hidden" name="saveId" value="${saveId ? '1' : ''}">
            <input type="hidden" name="autoLogin" value="${autoLogin ? '1' : ''}">
            <input type="text" name="code" placeholder="6자리 코드" maxlength="6" required autocomplete="one-time-code">
            <button type="submit" class="btn-primary" style="width:100%; margin-top:6px;">확인</button>
          </form>
        </body></html>
      `);
    }
    applyLoginCookies(res, username.trim(), !!saveId, !!autoLogin);
    logActivity(username.trim(), '로그인', '');
    res.redirect('/admin');
  } else {
    res.send(`
      <!DOCTYPE html>
      <html><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1">${THEME_STYLE}</head>
      <body style="display:flex; justify-content:center; align-items:center; height:100vh;">
        ${RADAR_BG}
        <div class="glass" style="padding:32px; text-align:center;">
          <p style="color:#ff3860;">아이디 또는 비밀번호가 틀렸어요.</p>
          <a href="/admin/login">다시 시도</a>
        </div>
      </body></html>
    `);
  }
});

app.post('/admin/login/verify-2fa', (req, res) => {
  const { pending, code, saveId, autoLogin } = req.body;
  const username = parsePendingToken(pending);
  if (!username) return res.status(400).send('세션이 만료됐어요. <a href="/admin/login">다시 로그인</a>');
  const users = loadUsers();
  const user = users[username];
  if (!user || !user.totpEnabled || !verifyTotpCode(user.totpSecret, code)) {
    return res.send(`
      <!DOCTYPE html>
      <html><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1">${THEME_STYLE}</head>
      <body style="display:flex; justify-content:center; align-items:center; height:100vh;">
        ${RADAR_BG}
        <div class="glass" style="padding:32px; text-align:center;">
          <p style="color:#ff3860;">인증 코드가 틀렸어요.</p>
          <a href="/admin/login">처음부터 다시</a>
        </div>
      </body></html>
    `);
  }
  applyLoginCookies(res, username, saveId === '1', autoLogin === '1');
  logActivity(username, '로그인 (2FA)', '');
  res.redirect('/admin');
});

app.get('/admin/signup', (req, res) => {
  res.send(`
    <!DOCTYPE html>
    <html><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1">${THEME_STYLE}</head>
    <body style="display:flex; justify-content:center; align-items:center; height:100vh;">
      ${RADAR_BG}
      <form method="POST" action="/admin/signup" class="glass" style="padding:36px; width:320px;">
        <div style="font-size:12px; color:#E0399B; letter-spacing:2px; margin-bottom:6px;">📝 회원가입</div>
        <h2 class="cute" style="margin:0 0 20px; color:#4A2545; font-weight:normal;">회원가입</h2>
        <input type="text" name="username" placeholder="아이디 (영문/숫자 추천)" required autocomplete="off">
        <input type="password" name="password" placeholder="비밀번호" required autocomplete="new-password">
        <input type="password" name="passwordConfirm" placeholder="비밀번호 확인" required autocomplete="new-password">
        <input type="email" name="email" placeholder="이메일 (아이디·비밀번호 찾기용)" required>
        <input type="text" name="referrer" placeholder="초대 코드 (관리자에게 문의)" required autocomplete="off">
        <button type="submit" class="btn-primary" style="width:100%; margin-top:6px;">가입하기</button>
        <div style="text-align:center; margin-top:14px; font-size:11px;">
          <a href="/admin/login" style="color:#8A6A93;">← 로그인으로 돌아가기</a>
        </div>
      </form>
    </body></html>
  `);
});

app.post('/admin/signup', (req, res) => {
  const { username, password, passwordConfirm, email, referrer } = req.body;
  const name = (username || '').trim();
  const mail = (email || '').trim().toLowerCase();
  const inviteCode = (referrer || '').trim().toUpperCase();

  function fail(msg) {
    res.send(`
      <!DOCTYPE html>
      <html><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1">${THEME_STYLE}</head>
      <body style="display:flex; justify-content:center; align-items:center; height:100vh;">
        ${RADAR_BG}
        <div class="glass" style="padding:32px; text-align:center;">
          <p style="color:#ff3860;">${msg}</p>
          <a href="/admin/signup">다시 시도</a>
        </div>
      </body></html>
    `);
  }

  if (!name || !/^[a-zA-Z0-9_-]{3,20}$/.test(name)) return fail('아이디는 영문/숫자로 3~20자로 입력해주세요.');
  if (!password || password.length < 4) return fail('비밀번호는 4자 이상으로 입력해주세요.');
  if (password !== passwordConfirm) return fail('비밀번호가 서로 달라요.');
  if (!mail || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(mail)) return fail('올바른 이메일 형식이 아니에요.');

  const invites = loadInvites();
  const inviteIdx = invites.findIndex((inv) => inv.code === inviteCode && !inv.used && !isInviteExpired(inv));
  if (inviteIdx === -1) return fail('초대 코드가 올바르지 않거나 이미 사용됐어요. 관리자에게 새 코드를 요청해주세요.');

  const users = loadUsers();
  if (users[name]) return fail('이미 있는 아이디예요.');
  const emailTaken = Object.values(users).some((u) => u.email && u.email.toLowerCase() === mail);
  if (emailTaken) return fail('이미 가입에 사용된 이메일이에요.');

  users[name] = {
    password: hashPassword(password), isAdmin: false, youtubeId: '', email: mail,
    nickname: '', avatarUrl: '', referredBy: invites[inviteIdx].code, totpSecret: '', totpEnabled: false,
    subscriptionType: 'period', subscriptionExpiresAt: addMonthsToTodayKST(1),
    createdAt: getTodayKST(), adminNote: ''
  };
  saveUsers(users);

  invites[inviteIdx].used = true;
  invites[inviteIdx].usedBy = name;
  invites[inviteIdx].usedAt = new Date().toISOString();
  saveInvites(invites);

  logActivity(name, '회원가입', '초대코드 사용: ' + inviteCode);

  applyLoginCookies(res, name, false, false);
  res.redirect('/admin');
});

app.get('/admin/find-id', (req, res) => {
  res.send(`
    <!DOCTYPE html>
    <html><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1">${THEME_STYLE}</head>
    <body style="display:flex; justify-content:center; align-items:center; height:100vh;">
      ${RADAR_BG}
      <form method="POST" action="/admin/find-id" class="glass" style="padding:36px; width:320px;">
        <div style="font-size:12px; color:#E0399B; letter-spacing:2px; margin-bottom:6px;">🔎 아이디 찾기</div>
        <h2 class="cute" style="margin:0 0 20px; color:#4A2545; font-weight:normal;">아이디 찾기</h2>
        <input type="email" name="email" placeholder="가입할 때 등록한 이메일" required>
        <button type="submit" class="btn-primary" style="width:100%; margin-top:6px;">찾기</button>
        <div style="text-align:center; margin-top:14px; font-size:11px;">
          <a href="/admin/login" style="color:#8A6A93;">← 로그인으로 돌아가기</a>
        </div>
      </form>
    </body></html>
  `);
});

app.post('/admin/find-id', (req, res) => {
  const mail = (req.body.email || '').trim().toLowerCase();
  const users = loadUsers();
  const matches = Object.keys(users).filter((u) => users[u].email && users[u].email.toLowerCase() === mail);
  res.send(`
    <!DOCTYPE html>
    <html><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1">${THEME_STYLE}</head>
    <body style="display:flex; justify-content:center; align-items:center; height:100vh;">
      ${RADAR_BG}
      <div class="glass" style="padding:32px; text-align:center; width:320px;">
        ${matches.length
          ? `<p style="color:#4A2545;">이 이메일로 가입된 아이디예요:</p><p style="color:#E0399B; font-weight:800; font-size:16px;">${matches.map(escapeHtml).join(', ')}</p>`
          : `<p style="color:#ff3860;">이 이메일로 가입된 아이디가 없어요.</p>`}
        <a href="/admin/login" style="color:#8A6A93; font-size:12px;">← 로그인으로 돌아가기</a>
      </div>
    </body></html>
  `);
});

app.get('/admin/reset-password', (req, res) => {
  res.send(`
    <!DOCTYPE html>
    <html><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1">${THEME_STYLE}</head>
    <body style="display:flex; justify-content:center; align-items:center; height:100vh;">
      ${RADAR_BG}
      <form method="POST" action="/admin/reset-password" class="glass" style="padding:36px; width:320px;">
        <div style="font-size:12px; color:#E0399B; letter-spacing:2px; margin-bottom:6px;">🔑 비밀번호 찾기</div>
        <h2 class="cute" style="margin:0 0 20px; color:#4A2545; font-weight:normal;">비밀번호 찾기</h2>
        <input type="text" name="username" placeholder="아이디" required autocomplete="off">
        <input type="email" name="email" placeholder="가입할 때 등록한 이메일" required autocomplete="off">
        <input type="password" name="newPassword" placeholder="새 비밀번호" required autocomplete="new-password">
        <button type="submit" class="btn-primary" style="width:100%; margin-top:6px;">비밀번호 변경</button>
        <div style="text-align:center; margin-top:14px; font-size:11px;">
          <a href="/admin/login" style="color:#8A6A93;">← 로그인으로 돌아가기</a>
        </div>
      </form>
    </body></html>
  `);
});

app.post('/admin/reset-password', (req, res) => {
  const name = (req.body.username || '').trim();
  const mail = (req.body.email || '').trim().toLowerCase();
  const newPassword = req.body.newPassword || '';
  const users = loadUsers();
  const user = users[name];

  function fail(msg) {
    res.send(`
      <!DOCTYPE html>
      <html><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1">${THEME_STYLE}</head>
      <body style="display:flex; justify-content:center; align-items:center; height:100vh;">
        ${RADAR_BG}
        <div class="glass" style="padding:32px; text-align:center;">
          <p style="color:#ff3860;">${msg}</p>
          <a href="/admin/reset-password">다시 시도</a>
        </div>
      </body></html>
    `);
  }

  if (!user || !user.email || user.email.toLowerCase() !== mail) {
    return fail('아이디와 이메일이 일치하지 않아요.');
  }
  if (newPassword.length < 4) return fail('비밀번호는 4자 이상으로 입력해주세요.');

  user.password = hashPassword(newPassword);
  saveUsers(users);

  res.send(`
    <!DOCTYPE html>
    <html><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1">${THEME_STYLE}</head>
    <body style="display:flex; justify-content:center; align-items:center; height:100vh;">
      ${RADAR_BG}
      <div class="glass" style="padding:32px; text-align:center;">
        <p style="color:#6EE7B7;">비밀번호가 변경됐어요!</p>
        <a href="/admin/login" style="color:#E0399B;">로그인하러 가기</a>
      </div>
    </body></html>
  `);
});

// 수정 화면
app.get('/admin/edit/:code', (req, res) => {
  if (!isLoggedIn(req)) return res.redirect('/admin/login');
  const links = loadLinks();
  const code = req.params.code;
  const link = links[code];
  if (!link) return res.status(404).send('링크를 찾을 수 없어요');
  if (!isAdminUser(req) && link.owner !== getCurrentUser(req)) {
    return res.status(403).send('이 링크에 대한 권한이 없어요');
  }
  const host = req.protocol + '://' + req.get('host');

  res.send(`
    <!DOCTYPE html>
    <html><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1">${THEME_STYLE}</head>
    <body style="padding:32px;">
      ${RADAR_BG}
      <div class="glass" style="max-width:420px; padding:28px; margin:0 auto;">
        <div style="font-size:12px; color:#E0399B; letter-spacing:2px; margin-bottom:6px;">✏️ 링크 수정</div>
        <h2 class="cute" style="margin:0 0 18px; color:#4A2545; font-weight:normal;">${escapeHtml(code)} 수정</h2>
        <form method="POST" action="/admin/edit">
          <input type="hidden" name="code" value="${escapeHtml(code)}">
          <label style="font-size:12px; color:#E0399B;">쿠팡 링크</label>
          <input type="text" name="url" value="${escapeHtml(link.url)}" required>
          <label style="font-size:12px; color:#E0399B;">제목</label>
          <input type="text" name="title" value="${escapeHtml(link.title || '')}">
          <label style="font-size:12px; color:#E0399B;">설명</label>
          <input type="text" name="description" value="${escapeHtml(link.description || '')}">
          <label style="font-size:12px; color:#E0399B;">이미지 주소</label>
          <input type="text" name="image" id="editImageInput" value="${escapeHtml(link.image || '')}" oninput="updateEditPreview()">
          <img id="editImagePreview" src="${escapeHtml(link.image ? imgProxyUrl(host, link.image) : '')}" style="width:100%; max-height:180px; object-fit:cover; border-radius:16px; margin-bottom:16px; display:${link.image ? 'block' : 'none'}; background:#FFF5FA; border:1px solid rgba(255,111,181,0.24);" onerror="this.style.display='none';" onload="this.style.display='block';">
          <label style="font-size:12px; color:#E0399B;">카테고리</label>
          <select id="categorySelectEdit" onchange="onCategorySelectChange(this, 'categoryCustomEdit')" style="width:100%;">${categoryOptionsHtml(link.category || '')}</select>
          <input type="text" id="categoryCustomEdit" name="category" value="${escapeHtml(link.category || '')}" placeholder="카테고리 직접 입력" style="display:${(link.category && !COUPANG_CATEGORIES.includes(link.category)) ? 'block' : 'none'};">
          <label style="font-size:12px; color:#E0399B;">폴더</label>
          <input type="text" name="folder" value="${escapeHtml(link.folder || '')}" placeholder="예: 여름프로모션">
          <label style="font-size:12px; color:#E0399B;">만료일 (선택)</label>
          <input type="date" name="expiresAt" value="${escapeHtml(link.expiresAt || '')}">
          <label style="font-size:12px; color:#E0399B;">클릭 알림 단위 (기본 100)</label>
          <input type="number" name="milestoneStep" value="${link.milestoneStep || 100}" min="1">
          <label style="font-size:12px; color:#E0399B;">가격 / 할인율</label>
          <div style="display:flex; gap:8px;">
            <input type="number" name="price" value="${link.price || ''}" placeholder="가격(원)" style="flex:1;">
            <input type="number" name="discountRate" value="${link.discountRate || ''}" placeholder="할인율%" style="flex:1;">
          </div>
          <label style="font-size:12px; color:#E0399B;">A/B 테스트</label>
          <div style="display:flex; gap:8px;">
            <input type="text" name="abGroup" value="${escapeHtml(link.abGroup || '')}" placeholder="그룹명" style="flex:1;">
            <select name="abVariant" style="flex:1;">
              <option value="" ${!link.abVariant ? 'selected' : ''}>A/B 아님</option>
              <option value="A" ${link.abVariant === 'A' ? 'selected' : ''}>A안</option>
              <option value="B" ${link.abVariant === 'B' ? 'selected' : ''}>B안</option>
            </select>
          </div>
          <button type="submit" class="btn-primary" style="width:100%; margin-top:12px;">저장하기</button>
        </form>
        <br>
        <a href="/admin" style="font-size:13px;">← 취소하고 돌아가기</a>
      </div>
      <script>
        function clientImgProxyUrl(url) {
          try {
            const host = window.location.origin;
            const hostname = new URL(url).hostname;
            if (hostname.indexOf('phinf.pstatic.net') !== -1) {
              return host + '/img-proxy?url=' + encodeURIComponent(url);
            }
          } catch (e) {}
          return url;
        }
        function updateEditPreview() {
          const val = document.getElementById('editImageInput').value.trim();
          const img = document.getElementById('editImagePreview');
          if (val) { img.src = clientImgProxyUrl(val); } else { img.style.display = 'none'; }
        }
        function onCategorySelectChange(select, customId) {
          const custom = document.getElementById(customId);
          if (select.value === '__custom__') {
            custom.style.display = 'block';
            custom.value = '';
            custom.focus();
          } else {
            custom.style.display = 'none';
            custom.value = select.value;
          }
        }
      </script>
    </body></html>
  `);
});

app.post('/admin/edit', (req, res) => {
  if (!isLoggedIn(req)) return res.redirect('/admin/login');
  const { code, url, title, description, image, category, expiresAt, milestoneStep, folder, price, discountRate, abGroup, abVariant } = req.body;
  const links = loadLinks();
  if (!links[code]) return res.status(404).send('링크를 찾을 수 없어요');
  if (!isAdminUser(req) && links[code].owner !== getCurrentUser(req)) {
    return res.status(403).send('이 링크에 대한 권한이 없어요');
  }

  links[code].url = url;
  links[code].title = title || '';
  links[code].description = description || '';
  links[code].image = cleanImageUrl(image) || '';
  links[code].category = category || '';
  links[code].expiresAt = expiresAt || '';
  links[code].milestoneStep = parseInt(milestoneStep, 10) || 100;
  links[code].folder = folder || '';
  links[code].price = price ? parseInt(price, 10) : null;
  links[code].discountRate = discountRate ? parseInt(discountRate, 10) : null;
  links[code].abGroup = abGroup || '';
  links[code].abVariant = abVariant || '';

  saveLinks(links);
  res.redirect('/admin');
});

app.post('/admin/api/convert', async (req, res) => {
  if (!isLoggedIn(req)) return res.status(401).json({ success: false, error: '로그인이 필요해요' });
  const keys = getEffectiveCoupangKeys(req);
  if (!keys) {
    return res.json({ success: false, error: isAdminUser(req) ? '관리자용 쿠팡 API 키가 설정되어 있지 않아요' : '먼저 "내 프로필"에서 쿠팡 API 키를 등록해주세요' });
  }
  try {
    const converted = await convertToDeeplink(req.body.url, keys.accessKey, keys.secretKey);
    res.json({ success: true, url: converted });
  } catch (e) {
    res.json({ success: false, error: e.message });
  }
});

app.get('/admin/api/search', async (req, res) => {
  if (!isLoggedIn(req)) return res.status(401).json({ success: false, error: '로그인이 필요해요' });
  const keys = getEffectiveCoupangKeys(req);
  if (!keys) {
    return res.json({ success: false, error: isAdminUser(req) ? '관리자용 쿠팡 API 키가 설정되어 있지 않아요' : '먼저 "내 프로필"에서 쿠팡 API 키를 등록해주세요', products: [] });
  }
  try {
    const products = await searchCoupangProducts(req.query.keyword || '', keys.accessKey, keys.secretKey);
    res.json({ success: true, products });
  } catch (e) {
    res.json({ success: false, error: e.message, products: [] });
  }
});

const DEFAULT_DISCLOSURES = {
  coupang: '쿠팡파트너스 활동으로 수수료를 받습니다',
  toss: '토스쇼핑 활동으로 수수료를 받습니다',
  naver: '네이버쇼핑커넥트 활동으로 수수료를 받습니다',
  olive: '올리브영 큐레이터 활동으로 수수료를 받습니다'
};
function getDisclosureTexts(user) {
  return Object.assign({}, DEFAULT_DISCLOSURES, (user && user.disclosureTexts) || {});
}

const COUPANG_CATEGORIES = [
  '로켓프레시', '도서/음반/DVD', '완구/취미', '스포츠/레저용품', '가전디지털',
  '가구/홈인테리어', 'R.LUX', '출산/유아동', 'Fashion', '뷰티',
  '반려동물용품', '생활용품', '자동차용품', '문구/오피스', '주방용품',
  '식품', '국내투어', '패션잡화'
];
function categoryOptionsHtml(selected) {
  const isCustom = selected && !COUPANG_CATEGORIES.includes(selected);
  let html = '<option value="">카테고리 선택 안 함</option>';
  html += COUPANG_CATEGORIES.map((c) =>
    `<option value="${escapeHtml(c)}" ${selected === c ? 'selected' : ''}>${escapeHtml(c)}</option>`
  ).join('');
  html += `<option value="__custom__" ${isCustom ? 'selected' : ''}>✏️ 직접 입력</option>`;
  return html;
}

// 네이버쇼핑커넥트 등에서 이미지 주소를 복사할 때 따옴표까지 같이 섞여 들어오는 경우가 있어서 자동으로 정리
function cleanImageUrl(url) {
  if (!url) return url;
  const trimmed = url.trim();
  try {
    const parsed = new URL(trimmed);
    if (parsed.hostname.includes('phinf.pstatic.net') && parsed.searchParams.has('src')) {
      let inner = parsed.searchParams.get('src');
      inner = inner.replace(/^"+|"+$/g, '').trim(); // 앞뒤에 붙은 따옴표 제거
      if (/^https?:\/\//.test(inner)) return inner;
    }
  } catch (e) {}
  return trimmed.replace(/^"+|"+$/g, ''); // 그 외의 경우도 혹시 앞뒤 따옴표만 있으면 제거
}

function detectPlatform(url) {
  if (/toss/i.test(url)) return 'toss';
  if (/naver\.me/i.test(url)) return 'naver';
  if (/oy\.run/i.test(url)) return 'olive';
  return 'coupang';
}

function computeStats(links, today) {
  const platforms = ['coupang', 'toss', 'naver', 'olive'];
  const totalToday = { coupang: 0, toss: 0, naver: 0, olive: 0 };
  const totalDaily = { coupang: {}, toss: {}, naver: {}, olive: {} };
  let totalTodayAll = 0;
  const totalDailyAll = {};
  const rankingEntries = [];
  const perLink = {};

  for (const code in links) {
    const link = links[code];
    const todayClicks = (link.dailyClicks && link.dailyClicks[today]) || 0;
    const platform = detectPlatform(link.url);
    const totalAllTime = Object.values(link.dailyClicks || {}).reduce((a, b) => a + b, 0);

    totalToday[platform] += todayClicks;
    totalTodayAll += todayClicks;
    for (const d in (link.dailyClicks || {})) {
      totalDaily[platform][d] = (totalDaily[platform][d] || 0) + link.dailyClicks[d];
      totalDailyAll[d] = (totalDailyAll[d] || 0) + link.dailyClicks[d];
    }

    rankingEntries.push({ code, platform, totalAllTime, title: link.title || code });
    perLink[code] = {
      todayClicks, totalAllTime, platform,
      dailyClicks: link.dailyClicks || {},
      title: link.title || code
    };
  }

  const overallRanking = [...rankingEntries].sort((a, b) => b.totalAllTime - a.totalAllTime).slice(0, 5);
  const platformRanking = {};
  platforms.forEach((p) => {
    platformRanking[p] = rankingEntries.filter((e) => e.platform === p).sort((a, b) => b.totalAllTime - a.totalAllTime).slice(0, 3);
  });

  return { platforms, totalToday, totalDaily, totalTodayAll, totalDailyAll, rankingEntries, perLink, overallRanking, platformRanking };
}

app.post('/admin/api/collect-prices-now', async (req, res) => {
  if (!isLoggedIn(req)) return res.status(401).json({ success: false });
  if (!isAdminUser(req)) return res.status(403).json({ success: false, error: '관리자만 실행할 수 있어요' });
  try {
    fs.writeFileSync(PRICE_STATE_FILE, JSON.stringify({ lastRun: '' })); // 강제로 다시 돌게
    await collectDailyPrices();
    res.json({ success: true });
  } catch (e) {
    res.json({ success: false, error: e.message });
  }
});

app.get('/admin/api/refresh', (req, res) => {
  if (!isLoggedIn(req)) return res.status(401).json({ success: false, error: '로그인이 필요해요' });
  const links = getVisibleLinks(req);
  const today = getTodayKST();
  const stats = computeStats(links, today);
  res.json({
    success: true,
    totalTodayAll: stats.totalTodayAll,
    totalDailyAll: stats.totalDailyAll,
    totalToday: stats.totalToday,
    totalDaily: stats.totalDaily,
    links: stats.perLink,
    overallRanking: stats.overallRanking,
    platformRanking: stats.platformRanking
  });
});

// 달력에서 고른 특정 날짜의 통계를 보여주는 API (과거 데이터 조회용)
app.get('/admin/api/stats-for-date', (req, res) => {
  if (!isLoggedIn(req)) return res.status(401).json({ success: false, error: '로그인이 필요해요' });
  const date = req.query.date;
  if (!date || !/^\d{4}-\d{2}-\d{2}$/.test(date)) {
    return res.json({ success: false, error: '날짜 형식이 올바르지 않아요' });
  }
  const links = getVisibleLinks(req);
  const totalByPlatform = { coupang: 0, toss: 0, naver: 0, olive: 0 };
  let totalAll = 0;
  const productList = [];

  for (const code in links) {
    const link = links[code];
    const clicks = (link.dailyClicks && link.dailyClicks[date]) || 0;
    if (clicks > 0) {
      const platform = detectPlatform(link.url);
      totalByPlatform[platform] += clicks;
      totalAll += clicks;
      productList.push({ code, title: link.title || code, platform, clicks });
    }
  }
  productList.sort((a, b) => b.clicks - a.clicks);

  res.json({
    success: true,
    date,
    totalAll,
    totalByPlatform,
    topProducts: productList.slice(0, 5)
  });
});

// 기간(범위)을 선택했을 때 합산 통계
app.get('/admin/api/stats-for-range', (req, res) => {
  if (!isLoggedIn(req)) return res.status(401).json({ success: false, error: '로그인이 필요해요' });
  const { start, end } = req.query;
  if (!start || !end || !/^\d{4}-\d{2}-\d{2}$/.test(start) || !/^\d{4}-\d{2}-\d{2}$/.test(end)) {
    return res.json({ success: false, error: '날짜 형식이 올바르지 않아요' });
  }
  const [from, to] = start <= end ? [start, end] : [end, start];
  const links = getVisibleLinks(req);
  const totalByPlatform = { coupang: 0, toss: 0, naver: 0, olive: 0 };
  let totalAll = 0;
  const productTotals = {};

  for (const code in links) {
    const link = links[code];
    const platform = detectPlatform(link.url);
    let productSum = 0;
    for (const d in (link.dailyClicks || {})) {
      if (d >= from && d <= to) {
        const clicks = link.dailyClicks[d];
        totalByPlatform[platform] += clicks;
        totalAll += clicks;
        productSum += clicks;
      }
    }
    if (productSum > 0) productTotals[code] = { title: link.title || code, platform, clicks: productSum };
  }
  const topProducts = Object.values(productTotals).sort((a, b) => b.clicks - a.clicks).slice(0, 5);

  res.json({ success: true, start: from, end: to, totalAll, totalByPlatform, topProducts });
});

// 달력에 각 날짜별 클릭 합계를 표시해주기 위한 월별 데이터
app.get('/admin/api/month-totals', (req, res) => {
  if (!isLoggedIn(req)) return res.status(401).json({ success: false, error: '로그인이 필요해요' });
  const year = parseInt(req.query.year, 10);
  const month = parseInt(req.query.month, 10); // 1~12
  if (!year || !month) return res.json({ success: false, error: '연/월이 필요해요' });
  const prefix = String(year) + '-' + String(month).padStart(2, '0');
  const links = getVisibleLinks(req);
  const totals = {};
  for (const code in links) {
    const link = links[code];
    for (const d in (link.dailyClicks || {})) {
      if (d.startsWith(prefix)) totals[d] = (totals[d] || 0) + link.dailyClicks[d];
    }
  }
  res.json({ success: true, totals });
});

function csvEscape(val) {
  const s = String(val === undefined || val === null ? '' : val);
  if (/[",\n]/.test(s)) return '"' + s.replace(/"/g, '""') + '"';
  return s;
}

app.get('/admin/export.csv', (req, res) => {
  if (!isLoggedIn(req)) return res.redirect('/admin/login');
  const links = getVisibleLinks(req);
  const today = getTodayKST();
  const host = req.protocol + '://' + req.get('host');
  const rows = [['코드', '제목', '플랫폼', '카테고리', '짧은링크', '원본링크', '오늘클릭', '누적클릭', '만료일']];
  for (const code in links) {
    const link = links[code];
    const todayClicks = (link.dailyClicks && link.dailyClicks[today]) || 0;
    const totalAllTime = Object.values(link.dailyClicks || {}).reduce((a, b) => a + b, 0);
    rows.push([
      code, link.title || '', detectPlatform(link.url), link.category || '',
      `${host}/r/${code}`, link.url, todayClicks, totalAllTime, link.expiresAt || ''
    ]);
  }
  const csv = '\uFEFF' + rows.map(r => r.map(csvEscape).join(',')).join('\n');
  res.setHeader('Content-Type', 'text/csv; charset=utf-8');
  res.setHeader('Content-Disposition', 'attachment; filename="links.csv"');
  res.send(csv);
});

app.get('/admin', (req, res) => {
  if (!isLoggedIn(req)) return res.redirect('/admin/login');

  const currentUser = getCurrentUser(req);
  const isAdmin = isAdminUser(req);
  const myUserData = loadUsers()[currentUser] || {};
  if (isSubscriptionExpired(myUserData)) {
    cleanupExpiredUserLinks();
    return res.redirect('/admin/renew');
  }
  const viewingUser = (isAdmin && req.query.viewUser) ? req.query.viewUser : currentUser;
  const links = getVisibleLinks(req);
  const host = req.protocol + '://' + req.get('host');
  const today = getTodayKST();
  const stats = computeStats(links, today);
  const { platforms, totalToday, totalDaily, totalTodayAll, totalDailyAll, overallRanking, platformRanking } = stats;

  let cards = '';
  let idx = 0;
  const categorySet = new Set();
  const folderSet = new Set();
  const sourceLabels = { kakao: '카카오톡', threads: 'Threads', instagram: '인스타', naver_app: '네이버', direct: '직접입력', other: '기타' };

  const sortedCodes = Object.keys(links).sort((a, b) => (links[b].pinned ? 1 : 0) - (links[a].pinned ? 1 : 0));
  for (const code of sortedCodes) {
    idx++;
    const link = links[code];
    const shortUrl = `${host}/r/${code}`;
    const todayClicks = stats.perLink[code].todayClicks;
    const totalAllTime = stats.perLink[code].totalAllTime;
    const platform = stats.perLink[code].platform;
    const category = link.category || '';
    if (category) categorySet.add(category);
    const folder = link.folder || '';
    if (folder) folderSet.add(folder);
    const expired = isExpired(link);
    const milestoneStep = link.milestoneStep || 100;

    const dailyData = JSON.stringify(link.dailyClicks || {});
    const chartId = `chart_${idx}`;
    const proxiedImg = link.image ? imgProxyUrl(host, link.image) : '';
    const imgSrc = proxiedImg ? `${escapeHtml(proxiedImg)}${proxiedImg.includes('?') ? '&' : '?'}v=${idx}` : '';
    const qrSrc = `https://api.qrserver.com/v1/create-qr-code/?size=70x70&data=${encodeURIComponent(shortUrl)}`;

    const sourceEntries = Object.entries(link.sourceClicks || {}).sort((a, b) => b[1] - a[1]).slice(0, 3);
    const sourceHtml = sourceEntries.length
      ? sourceEntries.map(([k, v]) => `${sourceLabels[k] || k} ${v}`).join(' · ')
      : '아직 유입 기록 없음';

    const countryEntries = Object.entries(link.countryClicks || {}).sort((a, b) => b[1] - a[1]).slice(0, 3);
    const countryHtml = countryEntries.length
      ? countryEntries.map(([k, v]) => `${escapeHtml(k)} ${v}`).join(' · ')
      : '아직 지역 기록 없음';

    cards += `
      <div class="card glass" data-code="${escapeHtml(code)}" data-chart-id="${chartId}" data-category="${escapeHtml(category)}" data-folder="${escapeHtml(folder)}">
        <div style="display:flex; gap:10px; margin-bottom:8px;">
          ${imgSrc ? `<img src="${imgSrc}" class="thumb" style="flex:1; margin-bottom:0;" onclick="copyText('${escapeHtml(link.image)}', this)" title="클릭하면 사진 링크가 복사돼요">` : '<div style="flex:1;"></div>'}
        </div>
        <div style="display:flex; align-items:center; gap:8px; margin-bottom:6px;">
          <button type="button" onclick="event.preventDefault(); document.getElementById('pinform_${chartId}').submit();" title="${link.pinned ? '고정 해제' : '즐겨찾기 고정'}" style="background:none; border:none; font-size:20px; cursor:pointer; flex-shrink:0; padding:0; line-height:1;">${link.pinned ? '📌' : '📍'}</button>
          <form id="pinform_${chartId}" method="POST" action="/admin/toggle-pin" style="display:none;"><input type="hidden" name="code" value="${escapeHtml(code)}"></form>
          <div class="card-title" style="margin:0;">${escapeHtml(link.title || code)}</div>
        </div>
        <div style="display:flex; gap:6px; flex-wrap:wrap; margin-bottom:8px;">
          ${category ? `<span class="dest-label" style="background:rgba(255,111,181,0.16); color:#E0399B;">${escapeHtml(category)}</span>` : ''}
          ${folder ? `<span class="dest-label" style="background:rgba(176,132,245,0.18); color:#8A4FE0;">📁 ${escapeHtml(folder)}</span>` : ''}
          ${link.abGroup ? `<span class="dest-label yellow-emph" style="background:rgba(255,196,0,0.15); color:#E0A200;">AB:${escapeHtml(link.abGroup)}-${escapeHtml(link.abVariant || '?')}</span>` : ''}
          ${expired ? `<span class="dest-label" style="background:rgba(255,56,96,0.2); color:#ff3860;">만료됨</span>` : (link.expiresAt ? `<span class="dest-label" style="background:rgba(176,132,245,0.15); color:#8A4FE0;">~${escapeHtml(link.expiresAt)}</span>` : '')}
        </div>
        ${link.price ? `<div class="yellow-emph" style="font-size:13px; color:#E0A200; font-weight:800; margin-bottom:6px;">${link.price.toLocaleString()}원${link.discountRate ? ` <span style="font-size:11px; color:#ff3860;">${link.discountRate}%↓</span>` : ''}</div>` : ''}
        ${(() => {
          const ph = link.priceHistory || {};
          const dates = Object.keys(ph).sort();
          if (dates.length === 0) return '';
          const latest = ph[dates[dates.length - 1]];
          const prev = dates.length > 1 ? ph[dates[dates.length - 2]] : null;
          let diffHtml = '';
          if (prev !== null && prev !== latest) {
            const diff = latest - prev;
            diffHtml = diff > 0
              ? `<span style="color:#ff3860;">▲${diff.toLocaleString()}</span>`
              : `<span style="color:#3FBFA6;">▼${Math.abs(diff).toLocaleString()}</span>`;
          }
          const allValues = dates.map((d) => ph[d]);
          const lowest = Math.min(...allValues);
          const lowestHtml = latest === lowest
            ? `<span style="color:#3FBFA6;">🏆 역대 최저가!</span>`
            : `<span style="opacity:0.7;">역대 최저 ${lowest.toLocaleString()}원 대비 +${(latest - lowest).toLocaleString()}원</span>`;
          const priceChartId = 'pricechart_' + chartId;
          return `
            <div style="font-size:10px; color:#8A6A93; margin-bottom:2px;">🏷️ 쿠팡 실시간가 ${latest.toLocaleString()}원 ${diffHtml} <span style="opacity:0.6;">(${escapeHtml(dates[dates.length - 1])} 수집)</span></div>
            <div style="font-size:9px; color:#8A6A93; margin-bottom:6px;">${lowestHtml}</div>
            ${dates.length >= 2 ? `<div style="height:44px; position:relative; margin-bottom:8px;"><canvas id="${priceChartId}"></canvas></div>
            <script>
              window.__priceData_${priceChartId} = ${JSON.stringify(ph)};
              window.__priceHistoryAll = window.__priceHistoryAll || {};
              window.__priceHistoryAll[${JSON.stringify(code)}] = { history: ${JSON.stringify(ph)}, title: ${JSON.stringify(link.title || code)} };
            </script>` : ''}
          `;
        })()}
        <div class="pill-row">
          <div class="pill">🔗 ${shortUrl}</div>
          <button type="button" class="copy-btn" onclick="copyText('${shortUrl}', this)">복사</button>
        </div>
        <div class="dest">
          <span class="dest-label">연결 링크</span>
          <a href="${link.url}" target="_blank">${link.url}</a>
        </div>
        <div style="font-size:10px; color:#8A6A93; margin-bottom:4px;">📥 ${sourceHtml}</div>
        <div style="font-size:10px; color:#8A6A93; margin-bottom:8px;">🌍 ${countryHtml}</div>
        <button type="button" class="copy-btn" style="width:100%; margin-bottom:8px;" onclick='copyPromoText(${JSON.stringify(escapeHtml(link.title || code))}, ${link.price || 0}, ${link.discountRate || 0}, ${JSON.stringify(shortUrl)}, ${JSON.stringify(platform)})'>💬 카톡 공유 문구 복사</button>
        <div class="clicks mono" id="clicks_${chartId}">${todayClicks} <span>오늘 클릭</span></div>
        <div style="font-size:10px; color:#8A6A93; margin-top:-6px; margin-bottom:8px;" id="cum_${chartId}">누적 ${totalAllTime}회</div>

        <div style="display:flex; justify-content:space-between; align-items:flex-end; gap:8px;">
          <div class="chart-controls" style="margin-bottom:0;">
            <button class="range-btn active" data-range="30" data-target="${chartId}">1개월</button>
            <button class="range-btn" data-range="60" data-target="${chartId}">2개월</button>
            <button class="range-btn" data-range="90" data-target="${chartId}">3개월</button>
            <button class="range-btn" data-range="all" data-target="${chartId}">전체</button>
          </div>
          <img src="${qrSrc}" title="QR코드 (클릭하면 짧은 링크 복사)" style="width:40px; height:40px; border-radius:10px; background:#fff; padding:2px; cursor:pointer; flex-shrink:0;" onclick="copyText('${shortUrl}', this)">
        </div>
        <div style="height:90px; position:relative;"><canvas id="${chartId}"></canvas></div>

        <div class="action-row">
          <a href="/admin/edit/${encodeURIComponent(code)}" class="edit-btn">수정하기</a>
          <form method="POST" action="/admin/delete" onsubmit="return confirm('${escapeHtml(code)} 링크를 삭제할까요? 되돌릴 수 없어요.');" class="delete-form">
            <input type="hidden" name="code" value="${escapeHtml(code)}">
            <button type="submit" class="delete-btn">삭제하기</button>
          </form>
        </div>

        <script>
          window.__data_${chartId} = ${dailyData};
          window.__totalClicks = window.__totalClicks || {};
          window.__totalClicks[${JSON.stringify(code)}] = ${totalAllTime};
          window.__linkTitles = window.__linkTitles || {};
          window.__linkTitles[${JSON.stringify(code)}] = ${JSON.stringify(link.title || code)};
          window.__milestoneStep = window.__milestoneStep || {};
          window.__milestoneStep[${JSON.stringify(code)}] = ${milestoneStep};
          window.__linkFull = window.__linkFull || {};
          window.__linkFull[${JSON.stringify(code)}] = { title: ${JSON.stringify(link.title || code)}, today: ${todayClicks}, total: ${totalAllTime}, platform: ${JSON.stringify(detectPlatform(link.url))}, category: ${JSON.stringify(category)} };
        </script>
      </div>
    `;
  }

  const platformIcons = { coupang: '🚀', toss: '💳', naver: '🟢', olive: '💄' };
  const platformNames = { coupang: '쿠팡', toss: '토스', naver: '네이버', olive: '올리브영' };

  // ===== 관리자용 사용자 통계 계산 =====
  const allUsersData = loadUsers();
  const nonAdminUsernames = Object.keys(allUsersData).filter((u) => !allUsersData[u].isAdmin);
  const thisMonthPrefix = getTodayKST().slice(0, 7);
  const newThisMonthCount = nonAdminUsernames.filter((u) => (allUsersData[u].createdAt || '').startsWith(thisMonthPrefix)).length;
  const expiringSoonUsers = nonAdminUsernames.filter((u) => {
    const ud = allUsersData[u];
    if (ud.subscriptionType !== 'period' || !ud.subscriptionExpiresAt) return false;
    const diff = Math.ceil((new Date(ud.subscriptionExpiresAt) - new Date(getTodayKST())) / 86400000);
    return diff <= 3;
  });

  function buildRankingRows(list, showPlatform) {
    if (!list.length) return `<div style="font-size:12px; color:#8A6A93; padding:8px 0;">아직 클릭 기록이 없어요</div>`;
    const medals = ['🥇', '🥈', '🥉'];
    return list.map((item, i) => `
      <div style="display:flex; align-items:center; gap:10px; padding:8px 0; ${i < list.length - 1 ? 'border-bottom:1px solid rgba(255,111,181,0.14);' : ''}">
        <div style="width:24px; font-size:14px; text-align:center; flex-shrink:0;">${medals[i] || (i + 1)}</div>
        <div class="rank-name" style="flex:1; min-width:0; font-size:12px; color:#4A2545; overflow:hidden; text-overflow:ellipsis; white-space:nowrap;">
          ${showPlatform ? `<span style="opacity:0.7;">${platformIcons[item.platform]}</span> ` : ''}${escapeHtml(item.title)}
        </div>
        <div class="rank-amt" style="font-size:12px; font-weight:700; color:#E0A200; flex-shrink:0;">${item.totalAllTime}회</div>
      </div>
    `).join('');
  }

  const overallRankingHtml = buildRankingRows(overallRanking, true);

  const platformRankingBoxes = platforms.map((p) => {
    const list = platformRanking[p];
    return `
      <div class="glass" style="padding:18px;">
        <div class="eyebrow cute" style="font-size:13px; margin-bottom:8px;">${platformIcons[p]} ${platformNames[p]} 인기 상품</div>
        <div id="rankBody_${p}">${buildRankingRows(list, false)}</div>
      </div>
    `;
  }).join('');

  const html = `
  <!DOCTYPE html>
  <html>
  <head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <script src="https://cdnjs.cloudflare.com/ajax/libs/Chart.js/4.4.0/chart.umd.min.js"></script>
    ${THEME_STYLE}
    <style>
      .wrap { padding: 32px; max-width: 1400px; margin: 0 auto; }
      h1 { font-size: 24px; margin-bottom: 4px; color: #4A2545; letter-spacing: 0.5px; }
      .eyebrow { font-size: 12px; color: #E0399B; letter-spacing: 3px; margin-bottom: 6px; font-weight: 700; }
      .top-row { display: grid; grid-template-columns: repeat(4, minmax(0, 1fr)); gap: 16px; margin-bottom: 24px; }
      @media (max-width: 1100px) { .top-row { grid-template-columns: repeat(2, minmax(0, 1fr)); } }
      @media (max-width: 620px) { .top-row { grid-template-columns: minmax(0, 1fr); } .wrap { padding: 16px; } h1 { font-size: 20px; } }
      .total-box { padding: 20px; position: relative; overflow: hidden; display: flex; flex-direction: column; min-height: 280px; }
      .grand-box { padding: 30px 34px; position: relative; overflow: hidden; display: flex; flex-direction: column; }
      @media (max-width: 620px) { .grand-box { padding: 20px; } }
      .total-box::before {
        content: ''; position: absolute; top: -40%; right: -20%; width: 200px; height: 200px;
        background: radial-gradient(circle, rgba(255,111,181,0.28), transparent 70%); pointer-events: none;
      }
      .total-num { font-size: 46px; font-weight: 800; line-height: 1; color: #E0399B; font-family: 'Baloo 2', sans-serif; }
      .total-label { font-size: 12px; color: #8A6A93; margin-top: 8px; letter-spacing: 0.5px; margin-bottom: 16px; }
      .form-box { padding: 22px; }
      .grid { display: grid; grid-template-columns: repeat(4, 1fr); gap: 16px; }
      @media (max-width: 1100px) { .grid { grid-template-columns: repeat(2, 1fr); } }
      @media (max-width: 620px) { .grid { grid-template-columns: 1fr; } }
      .card { padding: 16px; overflow: visible; position: relative; z-index: 1; }
      .card > * { position: relative; z-index: 3; }
      .card::before {
        content: ''; position: absolute; top: 0; left: 16px; right: 16px; height: 3px; border-radius: 3px;
        background: linear-gradient(90deg, transparent, #FF6FB5, #B084F5, transparent);
        z-index: 2;
      }
      .thumb { width: 100%; height: 100px; object-fit: cover; border-radius: 14px; margin-bottom: 10px; border: 1px solid rgba(255,111,181,0.24); cursor: pointer; transition: opacity 0.15s; }
      .thumb:hover { opacity: 0.85; }
      .card-title { font-size: 14px; font-weight: 800; margin-bottom: 8px; color: #4A2545; }
      .pill-row { display: flex; align-items: center; gap: 6px; margin-bottom: 10px; }
      .pill { display: inline-block; background: rgba(255,111,181,0.12); border: 1px solid rgba(255,111,181,0.28); color: #E0399B; font-weight: 600; padding: 5px 10px; border-radius: 999px; font-size: 10px; word-break: break-all; flex: 1; min-width: 0; }
      .copy-btn { background: rgba(176,132,245,0.16); border: 1px solid rgba(176,132,245,0.34); color: #8A4FE0; font-weight: 700; padding: 5px 9px; border-radius: 999px; font-size: 10px; flex-shrink: 0; }
      .dest { background: rgba(255,111,181,0.06); border: 1px solid rgba(255,111,181,0.18); border-radius: 12px; padding: 9px; margin-bottom: 10px; font-size: 10px; }
      .dest-label { display: inline-block; background: rgba(255,111,181,0.18); color: #E0399B; border-radius: 6px; padding: 2px 6px; font-size: 9px; margin-right: 6px; letter-spacing: 0.5px; }
      .dest a { color: #8A6A93; text-decoration: none; word-break: break-all; }
      .clicks { font-size: 22px; font-weight: 800; margin-bottom: 8px; color: #E0A200; }
      .clicks span { font-size: 10px; color: #8A6A93; font-weight: normal; margin-left: 6px; letter-spacing: 0.5px; }
      .chart-controls { margin-bottom: 6px; }
      .range-btn { background: rgba(255,111,181,0.1); border: 1px solid rgba(255,111,181,0.22); color: #8A6A93; padding: 3px 8px; border-radius: 999px; font-size: 9px; margin-right: 4px; cursor: pointer; }
      .cat-btn { background: rgba(255,111,181,0.08); border: 1px solid rgba(255,111,181,0.22); color: #8A6A93; padding: 7px 16px; border-radius: 999px; font-size: 12px; cursor: pointer; }
      .cat-btn.active { background: rgba(255,111,181,0.24); border-color: #FF6FB5; color: #E0399B; }
      .sub-btn { background: rgba(176,132,245,0.1); border: 1px solid rgba(176,132,245,0.25); color: #8A6A93; padding: 4px 8px; border-radius: 6px; font-size: 10px; cursor: pointer; }
      .sub-btn.active { background: rgba(176,132,245,0.28); border-color: #B084F5; color: #4A2545; font-weight: 700; }
      .cmp-select { background: rgba(255,255,255,0.9); color: #4A2545; border: 1px solid rgba(255,111,181,0.24); border-radius: 12px; padding: 8px 10px; font-size: 12px; }

      .cal-text { color: #4A2545; }
      .cal-text-sub { color: #8A6A93; }
      .range-btn.active { background: rgba(255,111,181,0.22); border-color: #FF6FB5; color: #E0399B; }
      .action-row { display: flex; gap: 6px; margin-top: 10px; }
      .edit-btn { flex: 1; text-align:center; background: rgba(176,132,245,0.14); color: #8A4FE0; border: 1px solid rgba(176,132,245,0.28); padding: 6px 10px; border-radius: 10px; font-size: 11px; text-decoration:none; }
      .delete-form { flex: 1; margin: 0; }
      .delete-btn { background: rgba(255,56,96,0.1); color: #ff3860; border: 1px solid rgba(255,56,96,0.28); padding: 6px 10px; border-radius: 10px; font-size: 11px; width: 100%; }
      .unit-price { font-size: 11px; color: #B84FD6; margin-top: 2px; }
    </style>
  </head>
  <body>
    ${RADAR_BG}
    <div class="app-shell">
      <aside class="sidebar">
        <div class="sidebar-brand cute">반짝딜 ✨</div>
        <div class="sidebar-profile">
          <div class="sidebar-avatar">${myUserData.avatarUrl ? `<img src="${escapeHtml(myUserData.avatarUrl)}" onerror="this.parentElement.textContent='👤';">` : '👤'}</div>
          <div>
            <div class="sidebar-name">${escapeHtml(myUserData.nickname || currentUser)}${isAdmin ? ' (관리자)' : ''}</div>
            <a href="/admin/logout" class="sidebar-logout">로그아웃</a>
          </div>
        </div>
        <nav class="sidebar-nav">
          <button type="button" class="nav-item active" onclick="window.scrollTo({top:0, behavior:'smooth'});">🏠 대시보드</button>
          <button type="button" class="nav-item" onclick="togglePanel('profilePanel')">⚙️ 내 프로필</button>
          ${isAdmin ? `
          <button type="button" class="nav-item" onclick="togglePanel('invitePanel')">🎟️ 초대 코드</button>
          <button type="button" class="nav-item" onclick="togglePanel('statsPanel')">📊 사용자 통계</button>
          <button type="button" class="nav-item" onclick="togglePanel('usersPanel')">👥 사용자 관리</button>
          ` : ''}
          <button type="button" class="nav-item" onclick="document.getElementById('guideModal').style.display='flex';">📖 사용법</button>
          <button type="button" class="nav-item" id="soundToggleBtn" onclick="toggleSound()">🔇 소리 끄기</button>
        </nav>
        <svg class="sidebar-leaf" viewBox="0 0 200 260" xmlns="http://www.w3.org/2000/svg">
          <g fill="none" stroke="#FFC1DE" stroke-width="2.5" opacity="0.6">
            <path d="M20 250 C25 200, 55 160, 100 130 C90 170, 70 210, 55 250"/>
            <path d="M25 220 C50 190, 75 170, 105 155"/>
            <path d="M45 245 C55 215, 75 190, 95 175"/>
          </g>
        </svg>
      </aside>
      <main class="main-content">
      <div style="display:flex; align-items:center; justify-content:space-between; flex-wrap:wrap; gap:10px; margin-bottom:10px;">
        <div>
          <div class="eyebrow">💗 반짝반짝 대시보드 💗</div>
          ${!isAdmin ? `
          <div style="font-size:11px; margin-top:4px;">
            ${myUserData.subscriptionType === 'lifetime'
              ? `<span style="color:#3FBFA6;">♾️ 평생 이용 가능</span>`
              : `<span style="color:${isSubscriptionExpired(myUserData) ? '#ff3860' : '#E0A200'};">📅 이용기간: ~${escapeHtml(myUserData.subscriptionExpiresAt || '미설정')} (D${(() => {
                  if (!myUserData.subscriptionExpiresAt) return '-?';
                  const diff = Math.ceil((new Date(myUserData.subscriptionExpiresAt) - new Date(getTodayKST())) / 86400000);
                  return diff >= 0 ? '-' + diff : '+' + Math.abs(diff);
                })()})</span>`}
          </div>
          ` : ''}
          ${isAdmin && viewingUser !== currentUser ? `
          <div style="font-size:12px; color:#E0399B; margin-top:6px;">🔍 지금 보고 있는 사용자: <strong>${escapeHtml(viewingUser)}</strong>의 링크 &nbsp; <a href="/admin" style="color:#B84FD6;">← 내 링크로 돌아가기</a></div>
          ` : ''}
        </div>
      </div>

      <div id="profilePanel" class="glass" style="display:none; padding:20px 24px; margin-bottom:20px;">
        <div class="eyebrow cute" style="font-size:14px; margin-bottom:10px;">⚙️ 내 프로필 설정</div>
        <div style="display:flex; gap:20px; flex-wrap:wrap;">
          <form method="POST" action="/admin/settings/profile" style="flex:1; min-width:220px;">
            <input type="text" name="nickname" placeholder="닉네임" value="${escapeHtml(myUserData.nickname || '')}">
            <input type="text" name="realName" placeholder="이름 (관리자만 볼 수 있어요)" value="${escapeHtml(myUserData.realName || '')}">
            <input type="text" name="avatarUrl" placeholder="프로필 사진 주소 (https://...)" value="${escapeHtml(myUserData.avatarUrl || '')}">
            <button type="submit" class="btn-ghost" style="width:100%;">저장</button>
          </form>
          <form method="POST" action="/admin/settings/password" style="flex:1; min-width:220px;" autocomplete="off">
            <div class="eyebrow" style="margin-bottom:8px;">🔑 비밀번호 변경</div>
            <input type="password" name="currentPassword" placeholder="현재 비밀번호" required autocomplete="off">
            <input type="password" name="newPassword" placeholder="새 비밀번호" required autocomplete="new-password">
            <input type="password" name="newPasswordConfirm" placeholder="새 비밀번호 확인" required autocomplete="new-password">
            <button type="submit" class="btn-ghost" style="width:100%;">변경하기</button>
          </form>
          <div style="flex:1; min-width:220px;">
            <div class="eyebrow" style="margin-bottom:8px;">🛡️ 2단계 인증(2FA)</div>
            ${myUserData.totpEnabled ? `
              <p style="font-size:12px; color:#3FBFA6; margin-bottom:10px;">✔ 현재 활성화되어 있어요</p>
              <form method="POST" action="/admin/settings/2fa/disable">
                <button type="submit" class="btn-ghost" style="width:100%;">2FA 끄기</button>
              </form>
            ` : `
              <p style="font-size:11px; color:#8A6A93; margin-bottom:10px;">Google Authenticator 같은 앱으로 로그인 시 추가 인증을 요구해요.</p>
              <button type="button" class="btn-ghost" style="width:100%; margin-bottom:10px;" onclick="start2FA()">2FA 설정 시작</button>
              <div id="totpSetupBox"></div>
            `}
          </div>
        </div>

        <div style="height:1px; background:rgba(255,111,181,0.18); margin:18px 0 14px;"></div>
        <div class="eyebrow" style="margin-bottom:8px;">📋 플랫폼별 공정위 문구 (카톡 공유 문구 복사시 맨 위에 자동으로 붙어요)</div>
        <form method="POST" action="/admin/settings/disclosures">
          <div style="display:grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap:10px;">
            <div>
              <label style="font-size:11px; color:#8A6A93;">🚀 쿠팡</label>
              <input type="text" name="coupang" value="${escapeHtml(getDisclosureTexts(myUserData).coupang)}">
            </div>
            <div>
              <label style="font-size:11px; color:#8A6A93;">💳 토스</label>
              <input type="text" name="toss" value="${escapeHtml(getDisclosureTexts(myUserData).toss)}">
            </div>
            <div>
              <label style="font-size:11px; color:#8A6A93;">🟢 네이버</label>
              <input type="text" name="naver" value="${escapeHtml(getDisclosureTexts(myUserData).naver)}">
            </div>
            <div>
              <label style="font-size:11px; color:#8A6A93;">💄 올리브영</label>
              <input type="text" name="olive" value="${escapeHtml(getDisclosureTexts(myUserData).olive)}">
            </div>
          </div>
          <button type="submit" class="btn-ghost" style="width:100%; margin-top:8px;">문구 저장</button>
        </form>

        ${!isAdmin ? `
        <div style="height:1px; background:rgba(255,111,181,0.18); margin:18px 0 14px;"></div>
        <div class="eyebrow" style="margin-bottom:8px;">🔐 내 쿠팡 API 키 (2차 비밀번호로만 열람/변경 가능)</div>
        <p style="font-size:11px; color:#8A6A93; margin-bottom:10px;">등록해두면 검색·자동변환에는 비밀번호 입력 없이 바로 쓰여요. 다만 이 키를 다시 눈으로 "확인"하려면 2차 비밀번호가 필요하고, 관리자를 포함해 아무도 화면에서 직접 볼 수는 없어요.</p>
        <div style="display:flex; gap:16px; flex-wrap:wrap;">
          <div style="flex:1; min-width:220px;">
            <div style="font-size:11px; color:#8A6A93; margin-bottom:6px;">${myUserData.coupangKeyBlob ? '✔ 키가 등록되어 있어요' : '아직 등록된 키가 없어요'}</div>
            <input type="text" id="coupangAccessKeyInput" placeholder="Access Key">
            <input type="text" id="coupangSecretKeyInput" placeholder="Secret Key">
            <input type="password" id="coupangSecondPwSave" placeholder="2차 비밀번호 (새로 정하거나 기존 것 입력)" autocomplete="new-password">
            <button type="button" class="btn-ghost" style="width:100%;" onclick="saveCoupangKeys()">저장 (암호화됨)</button>
          </div>
          <div style="flex:1; min-width:220px;">
            <div style="font-size:11px; color:#8A6A93; margin-bottom:6px;">등록된 키 확인하기</div>
            <input type="password" id="coupangSecondPwUnlock" placeholder="2차 비밀번호" autocomplete="new-password">
            <button type="button" class="btn-ghost" style="width:100%; margin-bottom:10px;" onclick="unlockCoupangKeys()">잠금 해제하고 보기</button>
            <button type="button" class="btn-ghost" style="width:100%; margin-bottom:10px;" onclick="validateCoupangKeys()">🩺 키 상태 확인</button>
            <div id="coupangUnlockResult" class="yellow-emph" style="font-size:11px; color:#E0A200; word-break:break-all;"></div>
          </div>
        </div>
        ` : ''}
      </div>

      <button type="button" id="scrollTopBtn" onclick="window.scrollTo({top:0, behavior:'smooth'});" title="맨 위로" style="display:none; position:fixed; bottom:24px; right:24px; width:46px; height:46px; border-radius:50%; background:linear-gradient(135deg, #FF6FB5, #B084F5); border:none; color:#fff; font-size:18px; cursor:pointer; box-shadow:0 8px 20px rgba(255,111,181,0.4); z-index:900;">↑</button>

      <div id="guideModal" style="display:none; position:fixed; top:0; left:0; width:100%; height:100%; background:rgba(255,240,247,0.7); z-index:1000; align-items:center; justify-content:center;">
        <div class="glass" style="padding:28px; max-width:560px; width:90%; max-height:80vh; overflow-y:auto;">
          <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:14px;">
            <div class="eyebrow cute" style="font-size:16px;">📖 반짝딜 사용 설명서</div>
            <button type="button" class="btn-ghost" onclick="document.getElementById('guideModal').style.display='none';">닫기</button>
          </div>
          ${renderFeatureGuideHtml()}
        </div>
      </div>

      <script>window.__myDisclosures = ${JSON.stringify(getDisclosureTexts(myUserData))};</script>
      <div style="height:22px;"></div>

      <div class="grand-box total-box glass">
        <div style="display:flex; gap:28px; align-items:flex-start; flex-wrap:wrap;">
          <div style="flex:2 1 420px; min-width:0;">
            <div class="eyebrow cute" style="font-size:16px; margin-bottom:2px;">전체 종합 현황</div>
            <div class="eyebrow" style="margin-bottom:4px;">🌐 전체 플랫폼</div>
            <div class="total-num mono" id="num_all" style="font-size:56px;">${totalTodayAll}</div>
            <div class="total-label">오늘 클릭 · 쿠팡 + 토스 + 네이버 + 올리브영, 중복 IP 제외</div>
            <div class="chart-controls">
              <button class="range-btn active" data-range="30" data-target="chart_total_all">1개월</button>
              <button class="range-btn" data-range="60" data-target="chart_total_all">2개월</button>
              <button class="range-btn" data-range="90" data-target="chart_total_all">3개월</button>
              <button class="range-btn" data-range="all" data-target="chart_total_all">전체</button>
            </div>
            <div style="height:120px; position:relative;"><canvas id="chart_total_all" class="agg-chart"></canvas></div>
            <script>window.__data_chart_total_all = ${JSON.stringify(totalDailyAll)};</script>
          </div>
          <div style="flex:1 1 280px; min-width:0; border-left:1px solid rgba(255,111,181,0.2); padding-left:24px;">
            <div class="eyebrow cute" style="font-size:14px; margin-bottom:8px;">🗓️ 날짜별 방문 합계 조회</div>
            <div style="display:flex; align-items:center; justify-content:space-between; gap:8px; margin-bottom:6px;">
              <button type="button" class="btn-ghost" onclick="calMoveMonth(-1)" style="padding:4px 10px;">◀</button>
              <span id="calMonthLabel" class="cal-text" style="font-size:12px; font-weight:700;"></span>
              <button type="button" class="btn-ghost" onclick="calMoveMonth(1)" style="padding:4px 10px;">▶</button>
            </div>
            <label class="cal-text-sub" style="font-size:10px; display:flex; align-items:center; gap:6px; margin-bottom:8px;">
              <input type="checkbox" id="calRangeMode" style="width:auto; margin:0;" onchange="calResetSelection()"> 기간(범위)으로 선택하기
            </label>
            <div id="calGrid" style="display:grid; grid-template-columns:repeat(7,24px); gap:2px;"></div>
            <div id="calSelectedLabel" class="cal-text-sub" style="font-size:9px; margin-top:6px;"></div>
            <div id="statsDateResult" style="margin-top:10px;"></div>
          </div>
        </div>
      </div>

      <div style="height:20px;"></div>

      <div class="top-row">
        ${(() => {
          const labels = {
            coupang: ['쿠팡 현황', '쿠팡', '🚀'],
            toss: ['토스 현황', '토스', '💳'],
            naver: ['네이버 현황', '네이버', '🟢'],
            olive: ['올리브영 현황', '올리브영', '💄']
          };
          return platforms.map((p) => `
            <div class="total-box glass">
              <div style="width:44px; height:44px; border-radius:50%; background:rgba(255,111,181,0.14); display:flex; align-items:center; justify-content:center; font-size:20px; margin-bottom:10px;">${labels[p][2]}</div>
              <div class="eyebrow cute" style="font-size:14px; margin-bottom:2px;">${labels[p][0]}</div>
              <div class="total-num mono" id="num_${p}">${totalToday[p]}</div>
              <div class="total-label">오늘 클릭 · 중복 IP 제외</div>
              <div class="chart-controls">
                <button class="range-btn active" data-range="30" data-target="chart_total_${p}">1개월</button>
                <button class="range-btn" data-range="60" data-target="chart_total_${p}">2개월</button>
                <button class="range-btn" data-range="90" data-target="chart_total_${p}">3개월</button>
                <button class="range-btn" data-range="all" data-target="chart_total_${p}">전체</button>
              </div>
              <div style="height:100px; position:relative;"><canvas id="chart_total_${p}" class="agg-chart"></canvas></div>
              <script>window.__data_chart_total_${p} = ${JSON.stringify(totalDaily[p])};</script>
            </div>
          `).join('');
        })()}
      </div>

      <div class="form-box glass" style="margin-bottom:32px;">
        <div class="eyebrow" style="margin-bottom:14px;">🔗 새 링크 만들기</div>
        <form method="POST" action="/admin/create">
          <input type="text" name="code" id="codeInput" placeholder="짧은 코드 (예: test1)" required onblur="checkDuplicateCode()">
          <div style="display:flex; gap:8px; margin-bottom:4px;">
            <input type="text" name="url" id="urlInput" placeholder="쿠팡/토스 링크" style="flex:1; margin-bottom:0;" onpaste="extractUrlOnPaste(event)" oninput="checkDuplicateUrl()" required>
            <button type="button" onclick="convertLink()" class="btn-ghost" style="white-space:nowrap;">자동변환</button>
          </div>
          <div id="duplicateWarning" style="font-size:11px; color:#ff3860; margin-bottom:8px; display:none;">⚠ 이미 등록된 링크와 같아요</div>
          <button type="button" onclick="openSearchModal()" class="btn-ghost" style="width:100%; margin-bottom:12px;">🔍 상품 검색해서 채우기</button>
          <div style="display:flex; gap:12px;">
            <div style="flex:1;">
              <input type="text" name="title" id="titleInput" placeholder="제목 (미리보기에 보일 이름)">
              <input type="text" name="description" placeholder="설명 (선택)">
              <input type="text" name="image" id="createImageInput" placeholder="이미지 주소 (선택, https://...)" oninput="updateCreatePreview()">
            </div>
            <img id="createImagePreview" style="width:160px; height:130px; object-fit:cover; border-radius:16px; display:none; background:#FFF5FA; border:1px solid rgba(255,111,181,0.24); flex-shrink:0;" onerror="this.style.display='none';" onload="this.style.display='block';">
          </div>
          <div style="display:flex; gap:8px;">
            <select id="categorySelectNew" onchange="onCategorySelectChange(this, 'categoryCustomNew')" style="flex:1;">${categoryOptionsHtml('')}</select>
            <input type="text" id="categoryCustomNew" name="category" placeholder="카테고리 직접 입력" style="display:none; flex:1;">
            <input type="text" name="folder" placeholder="폴더 (선택, 예: 여름프로모션)" style="flex:1;">
          </div>
          <div style="display:flex; gap:8px;">
            <input type="number" name="price" placeholder="가격 (선택, 원)" style="flex:1;">
            <input type="number" name="discountRate" placeholder="할인율% (선택)" style="flex:1;">
          </div>
          <button type="submit" class="btn-primary" style="width:100%;">등록하기</button>
        </form>
      </div>

      <div id="searchModal" style="display:none; position:fixed; top:0; left:0; width:100%; height:100%; background:rgba(255,240,247,0.7); z-index:1000; align-items:center; justify-content:center;">
        <div class="glass" style="padding:26px; max-width:480px; width:90%; max-height:80vh; overflow-y:auto;">
          <div class="eyebrow">🔍 상품 검색</div>
          <h3 style="margin:6px 0 16px; color:#4A2545;">상품 검색</h3>
          <div style="display:flex; gap:8px; margin-bottom:16px;">
            <input type="text" id="searchKeyword" placeholder="상품 이름 입력" style="flex:1; margin-bottom:0;">
            <button onclick="doSearch()" class="btn-primary" style="white-space:nowrap;">검색</button>
          </div>
          <div id="searchResults"></div>
          <button onclick="closeSearchModal()" class="btn-ghost" style="margin-top:16px; width:100%;">닫기</button>
        </div>
      </div>

      ${isAdmin ? `
      <div id="invitePanel" style="display:none;">
      <div class="glass" style="padding:18px 22px; margin-bottom:20px;">
        <div class="eyebrow cute" style="font-size:14px; margin-bottom:10px;">🎟️ 초대 코드 관리 (관리자 전용)</div>
        <p style="font-size:11px; color:#8A6A93; margin-bottom:12px;">여기서 만든 코드는 딱 한 번만 가입에 쓸 수 있고, 정해둔 기간이 지나면 자동으로 무효화돼요.</p>
        <form method="POST" action="/admin/invites/create" style="margin-bottom:14px; display:flex; gap:8px; align-items:center;">
          <select name="validDays" style="width:140px;">
            <option value="3">3일 동안 유효</option>
            <option value="7" selected>7일 동안 유효</option>
            <option value="14">14일 동안 유효</option>
            <option value="30">30일 동안 유효</option>
          </select>
          <button type="submit" class="btn-ghost">➕ 새 초대 코드 발급</button>
        </form>
        <div style="max-height:200px; overflow-y:auto;">
          ${loadInvites().slice().reverse().map((inv) => {
            const expired = !inv.used && isInviteExpired(inv);
            const status = inv.used ? '✔ 사용됨 (' + escapeHtml(inv.usedBy) + ')' : (expired ? '⌛ 기간만료' : `⏳ ~${escapeHtml(inv.validUntil || '무제한')}까지`);
            return `
            <div style="display:flex; justify-content:space-between; align-items:center; padding:6px 0; border-bottom:1px solid rgba(255,111,181,0.12); font-size:12px;">
              <span class="mono invite-code" style="color:${(inv.used || expired) ? '#8A6A93' : '#E0A200'};">${escapeHtml(inv.code)}</span>
              <span style="color:${expired ? '#ff3860' : '#8A6A93'}; font-size:11px;">${status}</span>
            </div>
          `; }).join('') || '<div style="font-size:12px; color:#8A6A93;">아직 발급한 코드가 없어요</div>'}
        </div>
      </div>
      </div>

      <div id="statsPanel" style="display:none;">
      <div class="glass" style="padding:18px 22px; margin-bottom:20px;">
        <div class="eyebrow cute" style="font-size:14px; margin-bottom:10px;">📊 사용자 통계 요약</div>
        <div style="display:flex; gap:24px; flex-wrap:wrap;">
          <div><div style="font-size:22px; font-weight:800; color:#E0A200;">${nonAdminUsernames.length}</div><div style="font-size:10px; color:#8A6A93;">전체 사용자</div></div>
          <div><div style="font-size:22px; font-weight:800; color:#3FBFA6;">${newThisMonthCount}</div><div style="font-size:10px; color:#8A6A93;">이번 달 신규가입</div></div>
          <div><div style="font-size:22px; font-weight:800; color:${expiringSoonUsers.length ? '#ff3860' : '#8A6A93'};">${expiringSoonUsers.length}</div><div style="font-size:10px; color:#8A6A93;">곧 만료(3일 이내)</div></div>
        </div>
      </div>

      ${expiringSoonUsers.length ? `
      <div class="glass" style="padding:14px 22px; margin-bottom:20px; border-color:rgba(255,56,96,0.4);">
        <span style="font-size:12px; color:#ff3860; font-weight:700;">⚠️ 곧 만료되는 사용자:</span>
        <span style="font-size:12px; color:#4A2545;">
          ${expiringSoonUsers.map((u) => `${escapeHtml(u)}(${isSubscriptionExpired(allUsersData[u]) ? '만료됨' : 'D-' + Math.ceil((new Date(allUsersData[u].subscriptionExpiresAt) - new Date(getTodayKST())) / 86400000)})`).join(', ')}
        </span>
      </div>
      ` : ''}
      </div>

      <div id="usersPanel" style="display:none;">
      <div class="glass" style="padding:18px 22px; margin-bottom:20px;">
        <div class="eyebrow cute" style="font-size:14px; margin-bottom:10px;">👥 사용자 관리 (관리자 전용)</div>
        <div style="display:flex; flex-wrap:wrap; gap:16px;">
          <form method="POST" action="/admin/users/create" style="flex:1; min-width:240px;" autocomplete="off">
            <input type="text" name="username" placeholder="새 아이디" required autocomplete="off">
            <input type="password" name="password" placeholder="비밀번호" required autocomplete="new-password">
            <input type="email" name="email" placeholder="이메일 (선택)" autocomplete="off">
            <label style="font-size:12px; color:#8A6A93; display:flex; align-items:center; gap:6px; margin-bottom:12px;">
              <input type="checkbox" name="isAdmin" style="width:auto; margin:0;"> 관리자 권한 부여 (전체 링크 열람 가능)
            </label>
            <button type="submit" class="btn-ghost" style="width:100%;">계정 추가</button>
          </form>
          <div style="flex:2; min-width:360px;">
            <div style="display:flex; gap:8px; margin-bottom:8px;">
              <input type="text" id="userSearchInput" placeholder="🔎 아이디로 검색" oninput="filterUserRows()" style="flex:1; margin-bottom:0;">
            </div>
            <form method="POST" action="/admin/users/bulk-extend" id="bulkExtendForm" style="margin-bottom:8px;">
              <button type="submit" class="btn-ghost" style="font-size:11px; padding:6px 10px;" onclick="return confirm('선택한 사용자들의 이용기간을 오늘로부터 1개월 연장할까요?');">✅ 선택한 사용자 1개월 일괄 연장</button>
              <span id="bulkSelectedCount" style="font-size:10px; color:#8A6A93; margin-left:6px;">0명 선택됨</span>
              <div id="userListContainer" style="max-height:320px; overflow-y:auto; padding-right:4px; margin-top:8px;">
                ${Object.keys(allUsersData).map((u) => {
                  const ud = allUsersData[u];
                  const subLabel = ud.isAdmin ? '👑 관리자'
                    : (ud.subscriptionType === 'lifetime' ? '♾️ 평생'
                      : `📅~${ud.subscriptionExpiresAt || '미설정'}${isSubscriptionExpired(ud) ? ' <span style="color:#ff3860;">(만료)</span>' : ''}`);
                  return `
                  <div class="user-row" data-username="${escapeHtml(u.toLowerCase())}" style="display:flex; align-items:center; gap:6px; padding:6px 0; border-bottom:1px solid rgba(255,111,181,0.14); font-size:12px; flex-wrap:nowrap; overflow-x:auto;">
                    ${!ud.isAdmin ? `<input type="checkbox" name="usernames" value="${escapeHtml(u)}" form="bulkExtendForm" class="bulk-check" onchange="updateBulkCount()" style="width:auto; margin:0; flex-shrink:0;">` : '<span style="width:14px; flex-shrink:0;"></span>'}
                    <a href="/admin?viewUser=${encodeURIComponent(u)}" style="flex:0 0 auto; max-width:80px; overflow:hidden; text-overflow:ellipsis; white-space:nowrap; color:#B84FD6; text-decoration:none;" title="이 사용자의 링크 보기">${escapeHtml(u)}${ud.isAdmin ? ' 👑' : ''}</a>
                    ${u !== currentUser ? `
                    <form method="POST" action="/admin/users/reset-password" onsubmit="return confirm('${escapeHtml(u)} 계정 비밀번호를 123456으로 초기화할까요?');" style="margin:0; flex-shrink:0;">
                      <input type="hidden" name="username" value="${escapeHtml(u)}">
                      <button type="submit" style="background:none; border:1px solid rgba(176,132,245,0.3); color:#8A4FE0; font-size:9px; cursor:pointer; border-radius:6px; padding:3px 5px; white-space:nowrap;">비번초기화</button>
                    </form>
                    <form method="POST" action="/admin/users/delete" onsubmit="return confirm('${escapeHtml(u)} 계정을 삭제할까요? 이 계정이 만든 링크는 그대로 남아있어요.');" style="margin:0; flex-shrink:0;">
                      <input type="hidden" name="username" value="${escapeHtml(u)}">
                      <button type="submit" style="background:none; border:none; color:#ff3860; font-size:10px; cursor:pointer; white-space:nowrap;">삭제</button>
                    </form>` : '<span style="font-size:10px; color:#8A6A93; flex-shrink:0;">나</span>'}
                    ${!ud.isAdmin ? `
                    <span style="font-size:9px; color:#8A6A93; flex-shrink:0; white-space:nowrap;">${subLabel}</span>
                    <form method="POST" action="/admin/users/set-subscription" style="display:flex; align-items:center; gap:3px; margin:0; flex-shrink:0;">
                      <input type="hidden" name="username" value="${escapeHtml(u)}">
                      <button type="submit" name="type" value="lifetime" class="sub-btn ${ud.subscriptionType === 'lifetime' ? 'active' : ''}" style="white-space:nowrap;">평생</button>
                      <span style="font-size:9px; color:#8A6A93; flex-shrink:0; white-space:nowrap;">만료일</span>
                      <input type="date" name="expiresAt" value="${escapeHtml(ud.subscriptionExpiresAt || '')}" style="width:118px; margin:0; padding:3px 5px; font-size:9px;">
                      <button type="submit" name="type" value="period" class="sub-btn ${ud.subscriptionType === 'period' ? 'active' : ''}" style="white-space:nowrap;">기간설정</button>
                    </form>
                    <form method="POST" action="/admin/users/set-note" style="display:flex; align-items:center; gap:3px; margin:0 0 0 auto; flex-shrink:0;">
                      <input type="hidden" name="username" value="${escapeHtml(u)}">
                      <input type="text" name="note" value="${escapeHtml(ud.adminNote || '')}" placeholder="메모" style="width:70px; margin:0; padding:3px 5px; font-size:9px;">
                      <button type="submit" style="background:none; border:1px solid rgba(63,191,166,0.3); color:#3FBFA6; font-size:9px; cursor:pointer; border-radius:6px; padding:3px 5px; white-space:nowrap;">저장</button>
                    </form>
                    ` : ''}
                  </div>
                `; }).join('')}
              </div>
            </form>
          </div>
        </div>

        <div style="height:1px; background:rgba(255,111,181,0.18); margin:18px 0 14px;"></div>
        <div id="personalInfoGate">
          <div class="eyebrow" style="margin-bottom:8px;">🔒 개인정보 (이메일·추천인) — 관리자 비밀번호 재확인 필요</div>
          <div style="display:flex; gap:8px; flex-wrap:wrap;">
            <input type="password" id="reauthPassword" placeholder="관리자 비밀번호" autocomplete="new-password" style="flex:1; min-width:180px; margin-bottom:0;">
            <button type="button" class="btn-ghost" onclick="unlockPersonalInfo()">확인하고 보기</button>
          </div>
          <div id="personalInfoBody" style="margin-top:12px;"></div>
        </div>
      </div>

      <div class="glass" style="padding:18px 22px; margin-bottom:20px;">
        <div class="eyebrow cute" style="font-size:14px; margin-bottom:10px;">📜 최근 활동 로그</div>
        <div style="max-height:220px; overflow-y:auto;">
          ${loadActivityLog().slice(0, 30).map((a) => `
            <div style="font-size:11px; color:#8A6A93; padding:5px 0; border-bottom:1px solid rgba(255,111,181,0.1);">
              <span style="color:#8A6A93;">${escapeHtml(a.time)}</span> ·
              <span style="color:#B84FD6;">${escapeHtml(a.user)}</span> ·
              ${escapeHtml(a.action)} ${a.detail ? '(' + escapeHtml(a.detail) + ')' : ''}
            </div>
          `).join('') || '<div style="font-size:12px; color:#8A6A93;">아직 기록이 없어요</div>'}
        </div>
      </div>
      </div>
      ` : ''}

      ${categorySet.size ? `
      <div style="display:flex; gap:8px; flex-wrap:wrap; margin-bottom:12px;" id="categoryFilters">
        <button type="button" class="cat-btn active" data-cat="__all__" onclick="filterByCategory('__all__', this)">전체</button>
        ${[...categorySet].map(c => `<button type="button" class="cat-btn" data-cat="${escapeHtml(c)}" onclick="filterByCategory('${escapeHtml(c)}', this)">${escapeHtml(c)}</button>`).join('')}
      </div>
      ` : ''}

      ${folderSet.size ? `
      <div style="display:flex; gap:8px; flex-wrap:wrap; margin-bottom:16px;" id="folderFilters">
        <button type="button" class="cat-btn active" data-folder="__all__" onclick="filterByFolder('__all__', this)">📁 전체 폴더</button>
        ${[...folderSet].map(f => `<button type="button" class="cat-btn" data-folder="${escapeHtml(f)}" onclick="filterByFolder('${escapeHtml(f)}', this)">📁 ${escapeHtml(f)}</button>`).join('')}
      </div>
      ` : ''}

      ${(() => {
        const abGroups = {};
        for (const c in links) {
          if (links[c].abGroup) {
            abGroups[links[c].abGroup] = abGroups[links[c].abGroup] || [];
            abGroups[links[c].abGroup].push({ code: c, ...links[c], todayClicks: stats.perLink[c].todayClicks, totalAllTime: stats.perLink[c].totalAllTime });
          }
        }
        const groupNames = Object.keys(abGroups);
        if (!groupNames.length) return '';
        return `
        <div class="glass" style="padding:18px 22px; margin-bottom:20px;">
          <div class="eyebrow cute" style="font-size:14px; margin-bottom:10px;">🧪 A/B 테스트 결과</div>
          ${groupNames.map((g) => `
            <div style="margin-bottom:12px;">
              <div style="font-size:12px; color:#8A6A93; margin-bottom:6px;">그룹: ${escapeHtml(g)}</div>
              <div style="display:flex; gap:10px; flex-wrap:wrap;">
                ${abGroups[g].map((v) => `
                  <div style="flex:1; min-width:160px; background:rgba(255,111,181,0.06); border-radius:14px; padding:10px;">
                    <div style="font-size:11px; color:#E0399B; font-weight:800; margin-bottom:4px;">${escapeHtml(v.abVariant || '?')}안 · ${escapeHtml(v.title || v.code)}</div>
                    <div class="yellow-emph" style="font-size:11px; color:#E0A200;">오늘 ${v.todayClicks}회 · 누적 ${v.totalAllTime}회</div>
                  </div>
                `).join('')}
              </div>
            </div>
          `).join('')}
        </div>
        `;
      })()}

      <div class="grid" id="linkGrid">${cards}</div>
      </main>
    </div>

    <script>
      // 클립보드에 텍스트 복사 (버튼이면 잠깐 "복사됨!"으로 바뀜)
      async function copyText(text, el) {
        try {
          await navigator.clipboard.writeText(text);
        } catch (e) {
          const ta = document.createElement('textarea');
          ta.value = text;
          document.body.appendChild(ta);
          ta.select();
          try { document.execCommand('copy'); } catch (e2) {}
          document.body.removeChild(ta);
        }
        if (el && el.tagName === 'BUTTON') {
          const orig = el.textContent;
          el.textContent = '복사됨!';
          setTimeout(() => { el.textContent = orig; }, 1200);
        } else if (el) {
          const orig = el.style.opacity;
          el.style.opacity = '0.4';
          setTimeout(() => { el.style.opacity = orig || '1'; }, 200);
        }
      }

      // 상품명에서 개수/용량을 읽어서 개당 가격을 추정 (정확하지 않을 수 있음)
      function estimateUnitPrice(name, price) {
        const patterns = [
          { re: /(\\d+(?:\\.\\d+)?)\\s*(개입|개|EA|ea|pcs|입)/i, unit: '개' },
          { re: /(\\d+(?:\\.\\d+)?)\\s*(ml|ML)/i, unit: 'ml', per100: true },
          { re: /(\\d+(?:\\.\\d+)?)\\s*(g|G)(?![a-zA-Z])/i, unit: 'g', per100: true },
          { re: /(\\d+(?:\\.\\d+)?)\\s*(l|L)(?![a-zA-Z])/i, unit: 'L' },
          { re: /(\\d+(?:\\.\\d+)?)\\s*(kg|KG)/i, unit: 'kg' }
        ];
        for (const p of patterns) {
          const m = name.match(p.re);
          if (m) {
            const qty = parseFloat(m[1]);
            if (!qty || qty <= 0) continue;
            if (p.per100) {
              const per100 = (price / qty) * 100;
              return \`100\${p.unit}당 약 \${Math.round(per100).toLocaleString()}원\`;
            }
            const perUnit = price / qty;
            return \`\${p.unit}당 약 \${Math.round(perUnit).toLocaleString()}원\`;
          }
        }
        return null;
      }

      // 긴 공유 문구(공정위 문구+상품명+링크)를 붙여넣어도, 그 안의 인터넷 주소만 골라내서 넣어줌
      function extractUrlOnPaste(e) {
        const text = (e.clipboardData || window.clipboardData).getData('text');
        const match = text.match(/https?:\\/\\/\\S+/);
        if (match) {
          e.preventDefault();
          let url = match[0];
          // 링크 뒤에 붙어있을 수 있는 문장부호/괄호 등을 살짝 정리
          url = url.replace(/[)\\]}.,!?"'>]+$/, '');
          e.target.value = url;
        }
      }

      async function convertLink() {
        const input = document.getElementById('urlInput');
        const original = input.value.trim();
        if (!original) { alert('먼저 쿠팡 링크를 입력해주세요'); return; }
        input.disabled = true;
        try {
          const res = await fetch('/admin/api/convert', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ url: original })
          });
          const data = await res.json();
          if (data.success) {
            input.value = data.url;
          } else {
            alert('변환 실패: ' + data.error);
          }
        } catch (e) {
          alert('변환 중 오류가 발생했어요');
        }
        input.disabled = false;
      }

      function openSearchModal() {
        document.getElementById('searchModal').style.display = 'flex';
      }
      function closeSearchModal() {
        document.getElementById('searchModal').style.display = 'none';
      }

      let lastSearchResults = [];

      async function doSearch() {
        const keyword = document.getElementById('searchKeyword').value.trim();
        const resultsDiv = document.getElementById('searchResults');
        if (!keyword) return;
        resultsDiv.innerHTML = '검색 중...';
        try {
          const res = await fetch('/admin/api/search?keyword=' + encodeURIComponent(keyword));
          const data = await res.json();
          if (!data.success) {
            resultsDiv.innerHTML = '검색 실패: ' + data.error;
            return;
          }
          if (!data.products.length) {
            resultsDiv.innerHTML = '검색 결과가 없어요';
            return;
          }
          lastSearchResults = data.products;
          resultsDiv.innerHTML = data.products.map((p, i) => {
            const unitPrice = estimateUnitPrice(p.productName, p.productPrice);
            return \`
            <div style="display:flex; align-items:center; gap:14px; padding:12px; border-bottom:1px solid rgba(255,111,181,0.16); cursor:pointer;" onclick="selectProduct(\${i})">
              <img src="\${p.productImage}" style="width:64px; height:64px; object-fit:cover; border-radius:14px; flex-shrink:0; background:#FFF5FA; border:1px solid rgba(255,111,181,0.24);">
              <div style="flex:1; min-width:0;">
                <div style="font-size:13px; color:#4A2545; line-height:1.4;">\${p.productName}</div>
              </div>
              <div style="text-align:right; white-space:nowrap;">
                <div style="font-size:15px; font-weight:800; color:#E0399B;">\${Number(p.productPrice).toLocaleString()}원</div>
                \${unitPrice ? \`<div class="unit-price">\${unitPrice}</div>\` : ''}
              </div>
            </div>
          \`;
          }).join('');
        } catch (e) {
          resultsDiv.innerHTML = '검색 중 오류가 발생했어요';
        }
      }

      function selectProduct(i) {
        const p = lastSearchResults[i];
        document.getElementById('urlInput').value = p.productUrl;
        document.getElementById('titleInput').value = p.productName;
        document.getElementById('createImageInput').value = p.productImage;
        updateCreatePreview();
        closeSearchModal();
      }

      function clientImgProxyUrl(url) {
        try {
          const host = window.location.origin;
          const hostname = new URL(url).hostname;
          if (hostname.indexOf('phinf.pstatic.net') !== -1) {
            return host + '/img-proxy?url=' + encodeURIComponent(url);
          }
        } catch (e) {}
        return url;
      }
      function updateCreatePreview() {
        const val = document.getElementById('createImageInput').value.trim();
        const img = document.getElementById('createImagePreview');
        if (val) { img.src = clientImgProxyUrl(val); } else { img.style.display = 'none'; }
      }

      const charts = {};

      function buildChartData(rawData, rangeDays) {
        const today = new Date();
        const labels = [];
        const values = [];
        let days = rangeDays;
        const weekdayNames = ['일', '월', '화', '수', '목', '금', '토'];

        if (rangeDays === 'all') {
          const dates = Object.keys(rawData).sort();
          days = dates.length > 0
            ? Math.ceil((today - new Date(dates[0])) / (1000*60*60*24)) + 1
            : 1;
        }

        for (let i = days - 1; i >= 0; i--) {
          const d = new Date(today);
          d.setDate(d.getDate() - i);
          const key = d.toISOString().slice(0, 10);
          labels.push([key.slice(5), weekdayNames[d.getDay()]]);
          values.push(rawData[key] || 0);
        }
        return { labels, values };
      }

      function renderChart(chartId, rangeDays) {
        const raw = window['__data_' + chartId] || {};
        const { labels, values } = buildChartData(raw, rangeDays);
        const ctx = document.getElementById(chartId);
        if (!ctx) return;
        const isAgg = ctx.classList.contains('agg-chart');

        if (charts[chartId]) charts[chartId].destroy();

        const baseRadius = labels.length > 40 ? 0 : 3;
        let pointRadii = values.map(() => baseRadius);
        let pointColors = values.map(() => '#FF6FB5');

        const PEAK_MAX = '#FF2E9A';
        const PEAK_MIN = '#8A4FE0';
        let maxIdx = -1, minIdx = -1, maxVal = 0, minVal = 0;

        if (isAgg && values.length) {
          maxVal = Math.max(...values);
          minVal = Math.min(...values);
          maxIdx = values.lastIndexOf(maxVal);
          minIdx = values.indexOf(minVal);
          if (maxVal > 0) pointColors[maxIdx] = PEAK_MAX;
          if (maxVal !== minVal) pointColors[minIdx] = PEAK_MIN;
        }

        // 종합 그래프의 최고/최저점 위에 숫자를 표시해주는 커스텀 플러그인
        const extremaLabelPlugin = {
          id: 'extremaLabel_' + chartId,
          afterDatasetsDraw(chart) {
            if (!isAgg) return;
            const meta = chart.getDatasetMeta(0);
            const c = chart.ctx;
            const area = chart.chartArea;

            function drawLabel(pt, text, color) {
              c.save();
              c.font = 'bold 11px sans-serif';
              c.fillStyle = color;
              const edgeGap = 26; // 이 거리보다 끝에 가까우면 정렬을 바꿔줌
              let align = 'center';
              let x = pt.x;
              if (pt.x > area.right - edgeGap) {
                align = 'right';
                x = area.right;
              } else if (pt.x < area.left + edgeGap) {
                align = 'left';
                x = area.left;
              }
              c.textAlign = align;
              const y = Math.max(pt.y - 10, area.top + 10);
              c.fillText(text, x, y);
              c.restore();
            }

            if (maxVal > 0 && meta.data[maxIdx]) {
              drawLabel(meta.data[maxIdx], String(maxVal), PEAK_MAX);
            }
            if (maxVal !== minVal && meta.data[minIdx]) {
              drawLabel(meta.data[minIdx], String(minVal), PEAK_MIN);
            }
          }
        };

        charts[chartId] = new Chart(ctx, {
          type: 'line',
          plugins: [extremaLabelPlugin],
          data: {
            labels: labels,
            datasets: [{
              label: '클릭 수',
              data: values,
              borderColor: '#FF6FB5',
              backgroundColor: 'rgba(255,111,181,0.18)',
              fill: true,
              tension: 0.3,
              pointRadius: pointRadii,
              pointHoverRadius: pointRadii.map(r => Math.max(r, 5)),
              pointBackgroundColor: pointColors
            }]
          },
          options: {
            responsive: true,
            maintainAspectRatio: false,
            layout: { padding: { top: isAgg ? 22 : 4, right: isAgg ? 18 : 4, left: isAgg ? 8 : 0 } },
            plugins: {
              legend: { display: false },
              tooltip: {
                callbacks: {
                  title: (items) => {
                    const l = items[0].label;
                    return Array.isArray(l) ? l.join(' (') + ')' : l;
                  }
                }
              }
            },
            scales: {
              x: { ticks: { maxTicksLimit: 8, color: '#8A6A93' }, grid: { color: 'rgba(255,111,181,0.12)' } },
              y: { beginAtZero: true, ticks: { precision: 0, color: '#8A6A93' }, grid: { color: 'rgba(255,111,181,0.12)' } }
            }
          }
        });
      }

      // ===== 가격 변동 미니 그래프 =====
      function renderPriceCharts() {
        document.querySelectorAll('canvas[id^="pricechart_"]').forEach((canvas) => {
          const data = window['__priceData_' + canvas.id];
          if (!data) return;
          const dates = Object.keys(data).sort();
          const values = dates.map((d) => data[d]);
          new Chart(canvas, {
            type: 'line',
            data: {
              labels: dates.map((d) => d.slice(5)),
              datasets: [{
                data: values,
                borderColor: '#E0A200',
                backgroundColor: 'rgba(224,162,0,0.12)',
                fill: true,
                tension: 0.25,
                pointRadius: 2,
                pointBackgroundColor: '#E0A200'
              }]
            },
            options: {
              responsive: true,
              maintainAspectRatio: false,
              plugins: { legend: { display: false }, tooltip: { enabled: true } },
              scales: {
                x: { display: false },
                y: { display: false, beginAtZero: false }
              }
            }
          });
        });
      }
      renderPriceCharts();

      document.querySelectorAll('.total-box, .card').forEach(box => {
        const btn = box.querySelector('.range-btn.active');
        if (btn) renderChart(btn.dataset.target, '30');
      });

      document.querySelectorAll('.range-btn').forEach(btn => {
        btn.addEventListener('click', () => {
          const target = btn.dataset.target;
          const range = btn.dataset.range;
          btn.parentElement.querySelectorAll('.range-btn').forEach(b => b.classList.remove('active'));
          btn.classList.add('active');
          renderChart(target, range === 'all' ? 'all' : parseInt(range));
        });
      });

      // ===== 카테고리 + 폴더 필터 (같이 적용됨) =====
      let currentCategoryFilter = '__all__';
      let currentFolderFilter = '__all__';

      function applyFilters() {
        document.querySelectorAll('#linkGrid .card').forEach(card => {
          const catOk = currentCategoryFilter === '__all__' || card.dataset.category === currentCategoryFilter;
          const folderOk = currentFolderFilter === '__all__' || card.dataset.folder === currentFolderFilter;
          card.style.display = (catOk && folderOk) ? '' : 'none';
        });
      }

      function filterByCategory(cat, btn) {
        currentCategoryFilter = cat;
        document.querySelectorAll('#categoryFilters .cat-btn').forEach(b => b.classList.remove('active'));
        btn.classList.add('active');
        applyFilters();
      }

      function filterByFolder(folder, btn) {
        currentFolderFilter = folder;
        document.querySelectorAll('#folderFilters .cat-btn').forEach(b => b.classList.remove('active'));
        btn.classList.add('active');
        applyFilters();
      }

      // ===== 사운드 시스템 (외부 음원 파일 없이 Web Audio API로 직접 합성) =====
      let audioCtx = null;
      let soundOn = false;

      function ensureAudioCtx() {
        if (!audioCtx) audioCtx = new (window.AudioContext || window.webkitAudioContext)();
        if (audioCtx.state === 'suspended') audioCtx.resume();
        return audioCtx;
      }

      function playTone(freq, startDelay, duration, type, peakGain) {
        const ctx = ensureAudioCtx();
        const osc = ctx.createOscillator();
        const gain = ctx.createGain();
        osc.type = type || 'square';
        osc.frequency.value = freq;
        const t0 = ctx.currentTime + (startDelay || 0);
        gain.gain.setValueAtTime(0, t0);
        gain.gain.linearRampToValueAtTime(peakGain || 0.12, t0 + 0.02);
        gain.gain.exponentialRampToValueAtTime(0.001, t0 + (duration || 0.2));
        osc.connect(gain).connect(ctx.destination);
        osc.start(t0);
        osc.stop(t0 + (duration || 0.2) + 0.05);
      }

      // (유튜브 배경음악 기능은 삭제됨 — 아래 두 함수는 마일스톤 사운드 코드에서 참조하므로 빈 상태로 남겨둠)
      let ytPlayer = null;
      let ytVolume = 35;

      function duckMusic() {
        if (ytPlayer && ytPlayer.setVolume) {
          try { ytPlayer.setVolume(6); } catch (e) {}
        }
      }
      function restoreMusic() {
        if (ytPlayer && ytPlayer.setVolume) {
          try { ytPlayer.setVolume(ytVolume); } catch (e) {}
        }
      }

      // 조회수 100 단위 돌파: 짧은 2음 블립
      function playMilestone100() {
        playTone(660, 0, 0.12, 'square', 0.1);
        playTone(880, 0.1, 0.16, 'square', 0.1);
      }

      // 조회수 1000 단위 돌파: 더 크고 화려한 4음 팡파레
      function playMilestone1000() {
        [440, 660, 880, 1320].forEach((f, i) => playTone(f, i * 0.1, 0.35, 'sawtooth', 0.14));
        playTone(220, 0, 0.6, 'sine', 0.1);
      }

      // 브라우저 자체 음성합성으로 상품명을 읽어줌 (외부 음원 파일 필요 없음)
      // onDone 콜백이 있으면, 읽기가 끝난 뒤(또는 실패해도) 호출해줌 - 음악 볼륨 복구용
      function speakText(text, onDone) {
        if (!('speechSynthesis' in window)) {
          if (onDone) setTimeout(onDone, 1500);
          return;
        }
        try {
          speechSynthesis.cancel();
          const utter = new SpeechSynthesisUtterance(text);
          utter.lang = 'ko-KR';
          utter.rate = 1.05;
          utter.pitch = 1.1;
          if (onDone) { utter.onend = onDone; utter.onerror = onDone; }
          speechSynthesis.speak(utter);
        } catch (e) {
          if (onDone) onDone();
        }
      }

      // ===== 가격 하락 알림 =====
      function checkPriceDrops() {
        const all = window.__priceHistoryAll || {};
        for (const code in all) {
          const { history, title } = all[code];
          const dates = Object.keys(history).sort();
          if (dates.length < 1) continue;
          const latest = history[dates[dates.length - 1]];
          const key = 'radar_lastprice_' + code;
          const prevStr = localStorage.getItem(key);
          const prev = prevStr ? parseInt(prevStr, 10) : null;
          if (prev !== null && latest < prev) {
            const dropAmount = prev - latest;
            notifyMilestone('💸 가격 하락!', title + '가 ' + dropAmount.toLocaleString() + '원 내렸어요! (' + latest.toLocaleString() + '원)');
            if (soundOn) {
              duckMusic();
              playMilestone100();
              speakText(title + ' 가격이 ' + dropAmount.toLocaleString() + '원 내렸어요!', restoreMusic);
            }
          }
          localStorage.setItem(key, String(latest));
        }
      }

      function checkMilestones() {
        const totals = window.__totalClicks || {};
        const titles = window.__linkTitles || {};
        const steps = window.__milestoneStep || {};
        for (const code in totals) {
          const total = totals[code];
          const key = 'radar_milestone_' + code;
          const prev = parseInt(localStorage.getItem(key) || '0', 10);
          const step = steps[code] || 100;
          const bigStep = step * 10;
          if (total > prev) {
            const prevBig = Math.floor(prev / bigStep);
            const newBig = Math.floor(total / bigStep);
            const prevSmall = Math.floor(prev / step);
            const newSmall = Math.floor(total / step);
            const name = titles[code] || code;
            if (newBig > prevBig) {
              notifyMilestone('🎉 마일스톤 달성!', name + ' ' + (newBig * bigStep) + '번 돌파!');
            } else if (newSmall > prevSmall) {
              notifyMilestone('📈 클릭 증가', name + ' ' + (newSmall * step) + '번 돌파!');
            }
            if (soundOn) {
              if (newBig > prevBig) {
                duckMusic();
                playMilestone1000();
                speakText(name + ', ' + (newBig * bigStep) + '번 돌파!', restoreMusic);
              } else if (newSmall > prevSmall) {
                duckMusic();
                playMilestone100();
                speakText(name + ', ' + (newSmall * step) + '번 돌파!', restoreMusic);
              }
            }
          }
          localStorage.setItem(key, String(total));
        }
      }

      function togglePanel(id) {
        const el = document.getElementById(id);
        if (!el) return;
        el.style.display = el.style.display === 'none' ? 'block' : 'none';
      }

      function toggleSound() {
        const btn = document.getElementById('soundToggleBtn');
        soundOn = !soundOn;
        if (soundOn) {
          ensureAudioCtx();
          requestNotifyPermission();
          btn.textContent = '🔊 소리 켜짐';
          playTone(880, 0, 0.15, 'square', 0.12);
          playTone(1320, 0.12, 0.2, 'square', 0.1);
          checkMilestones();
          checkPriceDrops();
        } else {
          btn.textContent = '🔇 소리 끄기';
        }
      }

      // 소리를 못 낸 상태에서도 누적치는 계속 기록해둬서, 나중에 소리 켰을 때 놓치지 않게 함
      checkMilestones();
      checkPriceDrops();

      // ===== 실시간 자동 갱신 (F5 없이도 조회수/그래프/랭킹이 최신 상태로 업데이트됨) =====
      const platformIcons2 = { coupang: '🚀', toss: '💳', naver: '🟢', olive: '💄' };

      function buildRankingRowsClient(list, showPlatform) {
        if (!list.length) return '<div style="font-size:12px; color:#8A6A93; padding:8px 0;">아직 클릭 기록이 없어요</div>';
        const medals = ['🥇', '🥈', '🥉'];
        const esc = (s) => String(s).replace(/[&<>"']/g, (c) => ({ '&':'&amp;', '<':'&lt;', '>':'&gt;', '"':'&quot;', "'":'&#39;' }[c]));
        return list.map((item, i) => \`
          <div style="display:flex; align-items:center; gap:10px; padding:8px 0; \${i < list.length - 1 ? 'border-bottom:1px solid rgba(255,111,181,0.14);' : ''}">
            <div style="width:24px; font-size:14px; text-align:center; flex-shrink:0;">\${medals[i] || (i + 1)}</div>
            <div class="rank-name" style="flex:1; min-width:0; font-size:12px; color:#4A2545; overflow:hidden; text-overflow:ellipsis; white-space:nowrap;">
              \${showPlatform ? ('<span style="opacity:0.7;">' + platformIcons2[item.platform] + '</span> ') : ''}\${esc(item.title)}
            </div>
            <div class="rank-amt" style="font-size:12px; font-weight:700; color:#E0A200; flex-shrink:0;">\${item.totalAllTime}회</div>
          </div>
        \`).join('');
      }

      // 카드의 code ↔ chartId 매핑 (한 번만 만들어둠)
      const codeToChartId = {};
      document.querySelectorAll('.card[data-code]').forEach(card => {
        codeToChartId[card.dataset.code] = card.dataset.chartId;
      });

      async function refreshDashboard() {
        try {
          const res = await fetch('/admin/api/refresh');
          const data = await res.json();
          if (!data.success) return;

          // 종합 + 플랫폼별 숫자/그래프 갱신
          const numAllEl = document.getElementById('num_all');
          if (numAllEl) numAllEl.textContent = data.totalTodayAll;
          window.__data_chart_total_all = data.totalDailyAll;
          rerenderIfVisible('chart_total_all');

          ['coupang', 'toss', 'naver', 'olive'].forEach(p => {
            const el = document.getElementById('num_' + p);
            if (el) el.textContent = data.totalToday[p];
            window['__data_chart_total_' + p] = data.totalDaily[p];
            rerenderIfVisible('chart_total_' + p);

            const rankEl = document.getElementById('rankBody_' + p);
            if (rankEl) rankEl.innerHTML = buildRankingRowsClient(data.platformRanking[p], false);
          });

          const overallEl = document.getElementById('rankBody_all');
          if (overallEl) overallEl.innerHTML = buildRankingRowsClient(data.overallRanking, true);

          // 각 상품 카드 숫자/그래프 갱신
          for (const code in data.links) {
            const info = data.links[code];
            const chartId = codeToChartId[code];
            if (!chartId) continue;

            const clicksEl = document.getElementById('clicks_' + chartId);
            if (clicksEl) clicksEl.innerHTML = info.todayClicks + ' <span>오늘 클릭</span>';
            const cumEl = document.getElementById('cum_' + chartId);
            if (cumEl) cumEl.textContent = '누적 ' + info.totalAllTime + '회';

            window['__data_' + chartId] = info.dailyClicks;
            window.__totalClicks[code] = info.totalAllTime;
            window.__linkTitles[code] = info.title;
            rerenderIfVisible(chartId);
          }

          // 새로 갱신된 누적치 기준으로 마일스톤(100/1000 돌파) 다시 확인
          checkMilestones();
        } catch (e) {
          // 네트워크 오류 시 조용히 무시하고 다음 주기에 다시 시도
        }
      }

      function rerenderIfVisible(chartId) {
        const ctx = document.getElementById(chartId);
        if (!ctx) return;
        const activeBtn = ctx.closest('.total-box, .card')?.querySelector('.range-btn.active');
        const range = activeBtn ? activeBtn.dataset.range : '30';
        renderChart(chartId, range === 'all' ? 'all' : parseInt(range));
      }

      setInterval(refreshDashboard, 20000);

      // ===== 맨 위로 가기 버튼 =====
      window.addEventListener('scroll', () => {
        const btn = document.getElementById('scrollTopBtn');
        if (!btn) return;
        btn.style.display = window.scrollY > 400 ? 'block' : 'none';
      });

      // ===== 카카오톡 공유 문구 생성 =====
      function copyPromoText(title, price, discountRate, shortUrl, platform) {
        const disclosures = window.__myDisclosures || {};
        let text = '';
        if (platform && disclosures[platform]) {
          text += disclosures[platform] + '\\n';
        }
        text += title + '\\n';
        if (price) {
          text += '💰 ' + price.toLocaleString() + '원';
          if (discountRate) text += ' (' + discountRate + '% 할인)';
          text += '\\n';
        }
        text += '🔗 ' + shortUrl;
        copyText(text);
        alert('공유 문구가 복사됐어요! 카카오톡에 붙여넣기 해보세요.');
      }

      function onCategorySelectChange(select, customId) {
        const custom = document.getElementById(customId);
        if (select.value === '__custom__') {
          custom.style.display = 'block';
          custom.value = '';
          custom.focus();
        } else {
          custom.style.display = 'none';
          custom.value = select.value;
        }
      }

      // ===== 중복 링크 감지 =====
      let dupCheckTimer = null;
      function checkDuplicateUrl() {
        clearTimeout(dupCheckTimer);
        dupCheckTimer = setTimeout(async () => {
          const url = document.getElementById('urlInput').value.trim();
          const warning = document.getElementById('duplicateWarning');
          if (!url) { warning.style.display = 'none'; return; }
          try {
            const res = await fetch('/admin/api/check-duplicate?url=' + encodeURIComponent(url));
            const data = await res.json();
            warning.style.display = data.duplicate ? 'block' : 'none';
          } catch (e) {}
        }, 500);
      }

      // ===== 짧은 코드 중복 확인 =====
      async function checkDuplicateCode() {
        const code = document.getElementById('codeInput').value.trim();
        if (!code) return;
        try {
          const res = await fetch('/admin/api/check-code?code=' + encodeURIComponent(code));
          const data = await res.json();
          if (data.duplicate) {
            let msg = '"' + code + '"는 이미 존재하는 코드예요.';
            if (data.lastNumber !== null) {
              msg += '\\n같은 형식(' + data.prefix + '+숫자)의 마지막 번호는 ' + data.prefix + data.lastNumber + '예요. ' + data.prefix + (data.lastNumber + 1) + '부터 써보세요.';
            }
            alert(msg);
          }
        } catch (e) {}
      }

      // ===== 브라우저 알림 (탭이 열려있는 동안, 다른 화면 보고 있어도 표시됨) =====
      function requestNotifyPermission() {
        if ('Notification' in window && Notification.permission === 'default') {
          Notification.requestPermission();
        }
      }
      function notifyMilestone(title, body) {
        if ('Notification' in window && Notification.permission === 'granted') {
          try { new Notification(title, { body }); } catch (e) {}
        }
      }

      // ===== 쿠팡 API 키 유효성 검사 =====
      async function validateCoupangKeys() {
        try {
          const res = await fetch('/admin/settings/coupang-api/validate', { method: 'POST' });
          const data = await res.json();
          alert(data.valid ? '✔ 키가 정상적으로 작동해요' : '✖ 키에 문제가 있어요: ' + (data.error || ''));
        } catch (e) {
          alert('확인 중 오류가 발생했어요');
        }
      }

      // ===== 미니 달력 위젯 (쿠팡파트너스 실적창 스타일) =====
      const today_ = new Date(new Date().getTime() + 9 * 60 * 60 * 1000);
      let calYear = today_.getUTCFullYear();
      let calMonth = today_.getUTCMonth() + 1; // 1~12
      let calRangeStart = null;
      let calRangeEnd = null;
      const platformIconsCal = { coupang: '🚀', toss: '💳', naver: '🟢', olive: '💄' };

      function calPad(n) { return String(n).padStart(2, '0'); }

      async function renderCalendar() {
        document.getElementById('calMonthLabel').textContent = calYear + '년 ' + calMonth + '월';
        let totals = {};
        try {
          const res = await fetch('/admin/api/month-totals?year=' + calYear + '&month=' + calMonth);
          const data = await res.json();
          if (data.success) totals = data.totals;
        } catch (e) {}

        const numColor = '#4A2545';
        const countColor = '#E0A200';
        const todayBorder = '1.5px solid #E0399B';

        const firstDay = new Date(Date.UTC(calYear, calMonth - 1, 1)).getUTCDay(); // 0=일
        const daysInMonth = new Date(Date.UTC(calYear, calMonth, 0)).getUTCDate();
        const grid = document.getElementById('calGrid');
        let html = '';
        ['일', '월', '화', '수', '목', '금', '토'].forEach((w) => {
          html += '<div style="font-size:9px; color:#8A6A93; text-align:center;">' + w + '</div>';
        });
        for (let i = 0; i < firstDay; i++) html += '<div></div>';
        const todayStr = new Date(new Date().getTime() + 9 * 60 * 60 * 1000).toISOString().slice(0, 10);
        for (let d = 1; d <= daysInMonth; d++) {
          const dateStr = calYear + '-' + calPad(calMonth) + '-' + calPad(d);
          const count = totals[dateStr] || 0;
          const isToday = dateStr === todayStr;
          const inRange = calRangeStart && calRangeEnd && dateStr >= calRangeStart && dateStr <= calRangeEnd;
          const isSelected = dateStr === calRangeStart || dateStr === calRangeEnd;
          let bg = 'rgba(255,111,181,0.08)';
          if (isSelected) bg = 'rgba(255,111,181,0.5)';
          else if (inRange) bg = 'rgba(176,132,245,0.3)';
          html += '<button type="button" onclick="calDayClick(\\'' + dateStr + '\\')" style="width:24px; height:24px; border-radius:8px; border:' + (isToday ? todayBorder : 'none') + '; background:' + bg + '; color:' + numColor + '; font-size:8px; cursor:pointer; display:flex; flex-direction:column; align-items:center; justify-content:center; padding:0;">' +
            '<span>' + d + '</span>' + (count > 0 ? '<span style="font-size:6px; color:' + countColor + ';">' + count + '</span>' : '') +
            '</button>';
        }
        grid.innerHTML = html;
      }

      function calMoveMonth(delta) {
        calMonth += delta;
        if (calMonth > 12) { calMonth = 1; calYear++; }
        if (calMonth < 1) { calMonth = 12; calYear--; }
        renderCalendar();
      }

      function calResetSelection() {
        calRangeStart = null;
        calRangeEnd = null;
        document.getElementById('statsDateResult').innerHTML = '';
        document.getElementById('calSelectedLabel').textContent = '';
        renderCalendar();
      }

      function calDayClick(dateStr) {
        const rangeMode = document.getElementById('calRangeMode').checked;
        if (!rangeMode) {
          loadStatsForDate(dateStr);
          return;
        }
        if (!calRangeStart || (calRangeStart && calRangeEnd)) {
          calRangeStart = dateStr;
          calRangeEnd = null;
          document.getElementById('calSelectedLabel').textContent = '시작일: ' + dateStr + ' (종료일을 눌러주세요)';
        } else {
          calRangeEnd = dateStr;
          if (calRangeEnd < calRangeStart) { const t = calRangeStart; calRangeStart = calRangeEnd; calRangeEnd = t; }
          document.getElementById('calSelectedLabel').textContent = calRangeStart + ' ~ ' + calRangeEnd;
          loadStatsForRange(calRangeStart, calRangeEnd);
        }
        renderCalendar();
      }

      function renderStatsSummary(prefixLabel, totalAll, totalByPlatform, topProducts) {
        const box = document.getElementById('statsDateResult');
        let html = '<div class="rank-name" style="font-size:13px; margin-bottom:8px; display:inline-block;">' + prefixLabel + ' 전체 클릭: <span class="yellow-emph" style="color:#E0A200; font-weight:800;">' + totalAll + '</span></div>';
        html += '<div style="display:flex; gap:14px; flex-wrap:wrap; margin-bottom:10px; font-size:11px; color:#8A6A93;">';
        ['coupang', 'toss', 'naver', 'olive'].forEach((pl) => {
          html += '<span>' + platformIconsCal[pl] + ' ' + totalByPlatform[pl] + '</span>';
        });
        html += '</div>';
        if (topProducts.length) {
          html += '<div style="font-size:11px; color:#8A6A93; margin-bottom:6px;">인기 상품</div>';
          topProducts.forEach((item, i) => {
            html += '<div style="display:flex; justify-content:space-between; font-size:11px; padding:4px 0; border-bottom:1px solid rgba(255,111,181,0.1);">' +
              '<span class="rank-name">' + (i + 1) + '. ' + platformIconsCal[item.platform] + ' ' + item.title + '</span>' +
              '<span class="yellow-emph" style="color:#E0A200;">' + item.clicks + '회</span></div>';
          });
        } else {
          html += '<div style="font-size:11px; color:#8A6A93;">기록된 클릭이 없어요</div>';
        }
        box.innerHTML = html;
      }

      async function loadStatsForDate(date) {
        const box = document.getElementById('statsDateResult');
        box.innerHTML = '<div style="font-size:12px; color:#8A6A93;">불러오는 중...</div>';
        try {
          const res = await fetch('/admin/api/stats-for-date?date=' + encodeURIComponent(date));
          const data = await res.json();
          if (!data.success) { box.innerHTML = '<div style="font-size:12px; color:#ff3860;">' + (data.error || '조회 실패') + '</div>'; return; }
          renderStatsSummary('📅 ' + data.date, data.totalAll, data.totalByPlatform, data.topProducts);
        } catch (e) {
          box.innerHTML = '<div style="font-size:12px; color:#ff3860;">오류가 발생했어요</div>';
        }
      }

      async function loadStatsForRange(start, end) {
        const box = document.getElementById('statsDateResult');
        box.innerHTML = '<div style="font-size:12px; color:#8A6A93;">불러오는 중...</div>';
        try {
          const res = await fetch('/admin/api/stats-for-range?start=' + encodeURIComponent(start) + '&end=' + encodeURIComponent(end));
          const data = await res.json();
          if (!data.success) { box.innerHTML = '<div style="font-size:12px; color:#ff3860;">' + (data.error || '조회 실패') + '</div>'; return; }
          renderStatsSummary('📅 ' + data.start + ' ~ ' + data.end, data.totalAll, data.totalByPlatform, data.topProducts);
        } catch (e) {
          box.innerHTML = '<div style="font-size:12px; color:#ff3860;">오류가 발생했어요</div>';
        }
      }

      renderCalendar();

      // ===== 개인정보(이메일/추천인) 재인증 후 보기 =====
      function filterUserRows() {
        const q = document.getElementById('userSearchInput').value.trim().toLowerCase();
        document.querySelectorAll('.user-row').forEach((row) => {
          row.style.display = row.dataset.username.includes(q) ? '' : 'none';
        });
      }
      function updateBulkCount() {
        const count = document.querySelectorAll('.bulk-check:checked').length;
        const el = document.getElementById('bulkSelectedCount');
        if (el) el.textContent = count + '명 선택됨';
      }

      async function unlockPersonalInfo() {
        const pw = document.getElementById('reauthPassword').value;
        if (!pw) { alert('비밀번호를 입력해주세요'); return; }
        try {
          const res = await fetch('/admin/api/verify-admin-password', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ password: pw })
          });
          const data = await res.json();
          if (!data.success) { alert(data.error || '실패했어요'); return; }
          const body = document.getElementById('personalInfoBody');
          const rows = Object.keys(data.details).map((u) => {
            const d = data.details[u];
            return '<div style="display:flex; justify-content:space-between; font-size:11px; padding:5px 0; border-bottom:1px solid rgba(255,111,181,0.1);">' +
              '<span style="color:#4A2545;">' + u + '</span>' +
              '<span style="color:#8A6A93;">이름: ' + d.realName + ' · 닉네임: ' + d.nickname + ' · ' + d.email + ' · 추천인코드: ' + d.referredBy + '</span>' +
            '</div>';
          }).join('');
          body.innerHTML = rows;
          document.getElementById('reauthPassword').value = '';
        } catch (e) {
          alert('오류가 발생했어요');
        }
      }

      // ===== 2FA 설정 =====
      async function start2FA() {
        try {
          const res = await fetch('/admin/settings/2fa/start', { method: 'POST' });
          const data = await res.json();
          if (!data.success) { alert('시작 실패'); return; }
          const box = document.getElementById('totpSetupBox');
          box.innerHTML =
            '<img src="' + data.qrUrl + '" style="width:140px; height:140px; border-radius:14px; background:#fff; padding:6px; margin-bottom:8px;">' +
            '<div style="font-size:10px; color:#8A6A93; margin-bottom:8px; word-break:break-all;">시크릿: ' + data.secret + '</div>' +
            '<input type="text" id="totpCodeInput" placeholder="앱에 뜬 6자리 코드 입력" maxlength="6">' +
            '<button type="button" class="btn-primary" style="width:100%;" onclick="confirm2FA()">인증하고 켜기</button>';
        } catch (e) {
          alert('오류가 발생했어요');
        }
      }

      async function confirm2FA() {
        const code = document.getElementById('totpCodeInput').value;
        try {
          const res = await fetch('/admin/settings/2fa/confirm', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ code })
          });
          const data = await res.json();
          if (data.success) {
            alert('2FA가 활성화됐어요! 다음 로그인부터 코드가 필요해요.');
            location.reload();
          } else {
            alert(data.error || '실패했어요');
          }
        } catch (e) {
          alert('오류가 발생했어요');
        }
      }

      async function saveCoupangKeys() {
        const accessKey = document.getElementById('coupangAccessKeyInput').value.trim();
        const secretKey = document.getElementById('coupangSecretKeyInput').value.trim();
        const secondPassword = document.getElementById('coupangSecondPwSave').value;
        if (!accessKey || !secretKey || !secondPassword) { alert('전부 입력해주세요'); return; }
        try {
          const res = await fetch('/admin/settings/coupang-api/save', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ accessKey, secretKey, secondPassword })
          });
          const data = await res.json();
          if (data.success) {
            alert('저장됐어요! (암호화되어 저장되고, 이 2차 비밀번호를 입력해야만 다시 볼 수 있어요)');
            location.reload();
          } else {
            alert(data.error || '실패했어요');
          }
        } catch (e) {
          alert('오류가 발생했어요');
        }
      }

      async function unlockCoupangKeys() {
        const secondPassword = document.getElementById('coupangSecondPwUnlock').value;
        if (!secondPassword) { alert('2차 비밀번호를 입력해주세요'); return; }
        try {
          const res = await fetch('/admin/settings/coupang-api/unlock', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ secondPassword })
          });
          const data = await res.json();
          const box = document.getElementById('coupangUnlockResult');
          if (data.success) {
            box.innerHTML = 'Access Key: ' + data.accessKey + '<br>Secret Key: ' + data.secretKey + '<br><span style="color:#3FBFA6;">이 키는 검색/자동변환에 비밀번호 입력 없이 계속 쓰이고 있어요</span>';
          } else {
            box.innerHTML = '';
            alert(data.error || '실패했어요');
          }
        } catch (e) {
          alert('오류가 발생했어요');
        }
      }
    </script>
  </body>
  </html>
  `;
  res.send(html);
});

app.post('/admin/create', (req, res) => {
  if (!isLoggedIn(req)) return res.redirect('/admin/login');
  const owner = getCurrentUser(req);
  const { code, url, title, description, image, category, expiresAt, milestoneStep, folder, price, discountRate, abGroup, abVariant } = req.body;
  const links = loadLinks();
  links[code] = {
    url: url,
    title: title || '',
    description: description || '',
    image: cleanImageUrl(image) || '',
    category: category || '',
    folder: folder || '',
    expiresAt: expiresAt || '',
    milestoneStep: parseInt(milestoneStep, 10) || 100,
    price: price ? parseInt(price, 10) : null,
    discountRate: discountRate ? parseInt(discountRate, 10) : null,
    abGroup: abGroup || '',
    abVariant: abVariant || '',
    pinned: false,
    owner: owner,
    dailyClicks: {},
    sourceClicks: {},
    countryClicks: {}
  };
  saveLinks(links);
  res.redirect('/admin');
});

app.post('/admin/delete', (req, res) => {
  if (!isLoggedIn(req)) return res.redirect('/admin/login');
  const { code } = req.body;
  const links = loadLinks();
  if (links[code] && !isAdminUser(req) && links[code].owner !== getCurrentUser(req)) {
    return res.status(403).send('이 링크에 대한 권한이 없어요');
  }
  delete links[code];
  saveLinks(links);
  res.redirect('/admin');
});

app.post('/admin/toggle-pin', (req, res) => {
  if (!isLoggedIn(req)) return res.redirect('/admin/login');
  const { code } = req.body;
  const links = loadLinks();
  if (!links[code]) return res.redirect('/admin');
  if (!isAdminUser(req) && links[code].owner !== getCurrentUser(req)) {
    return res.status(403).send('이 링크에 대한 권한이 없어요');
  }
  links[code].pinned = !links[code].pinned;
  saveLinks(links);
  res.redirect('/admin');
});

app.get('/admin/api/check-duplicate', (req, res) => {
  if (!isLoggedIn(req)) return res.status(401).json({ success: false });
  const url = (req.query.url || '').trim();
  if (!url) return res.json({ duplicate: false });
  const links = getVisibleLinks(req);
  const match = Object.keys(links).find((code) => links[code].url === url);
  res.json({ duplicate: !!match, code: match || null });
});

app.get('/admin/api/check-code', (req, res) => {
  if (!isLoggedIn(req)) return res.status(401).json({ success: false });
  const code = (req.query.code || '').trim();
  if (!code) return res.json({ duplicate: false });
  const allLinks = loadLinks();
  const duplicate = !!allLinks[code];

  // "영어+숫자" 형태면(예: hana3), 같은 영어 앞부분을 쓰는 코드들 중 가장 큰 숫자를 찾아서 알려줌
  let prefix = null;
  let lastNumber = null;
  const m = code.match(/^([a-zA-Z]+)(\d+)$/);
  if (m) {
    prefix = m[1];
    let maxNum = -1;
    for (const c in allLinks) {
      const cm = c.match(/^([a-zA-Z]+)(\d+)$/);
      if (cm && cm[1].toLowerCase() === prefix.toLowerCase() && parseInt(cm[2], 10) > maxNum) {
        maxNum = parseInt(cm[2], 10);
      }
    }
    if (maxNum >= 0) lastNumber = maxNum;
  }
  res.json({ duplicate, prefix, lastNumber });
});

app.post('/admin/settings/coupang-api/validate', async (req, res) => {
  if (!isLoggedIn(req)) return res.status(401).json({ success: false, error: '로그인이 필요해요' });
  const keys = getEffectiveCoupangKeys(req);
  if (!keys) return res.json({ valid: false, error: '등록/잠금해제된 키가 없어요' });
  try {
    await searchCoupangProducts('테스트', keys.accessKey, keys.secretKey);
    res.json({ valid: true });
  } catch (e) {
    res.json({ valid: false, error: e.message });
  }
});

app.get('/admin/logout', (req, res) => {
  res.setHeader('Set-Cookie', 'radarSession=; HttpOnly; Path=/; Max-Age=0');
  res.redirect('/admin/login');
});

app.get('/admin/renew', (req, res) => {
  if (!isLoggedIn(req)) return res.redirect('/admin/login');
  const username = getCurrentUser(req);
  const user = loadUsers()[username];
  if (!isSubscriptionExpired(user)) return res.redirect('/admin');

  res.send(`
    <!DOCTYPE html>
    <html><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1">${THEME_STYLE}</head>
    <body style="display:flex; justify-content:center; align-items:center; height:100vh;">
      ${RADAR_BG}
      <form method="POST" action="/admin/renew" class="glass" style="padding:36px; width:340px; text-align:center;">
        <div style="font-size:32px; margin-bottom:10px;">⏳</div>
        <h2 class="cute" style="margin:0 0 10px; color:#4A2545; font-weight:normal;">이용 기간이 끝났어요</h2>
        <p style="font-size:12px; color:#8A6A93; margin-bottom:16px;">만료일: ${escapeHtml(user.subscriptionExpiresAt)}<br>새 인증코드를 입력하면 1개월 더 이용할 수 있어요.</p>
        <input type="text" name="renewCode" placeholder="인증코드" required autocomplete="off" style="text-align:center;">
        <button type="submit" class="btn-primary" style="width:100%; margin-top:6px;">인증코드로 갱신하기</button>
        <div style="margin-top:14px;"><a href="/admin/logout" style="color:#8A6A93; font-size:11px;">로그아웃</a></div>
      </form>
    </body></html>
  `);
});

app.post('/admin/renew', (req, res) => {
  if (!isLoggedIn(req)) return res.redirect('/admin/login');
  const username = getCurrentUser(req);
  const renewCode = (req.body.renewCode || '').trim().toUpperCase();

  const invites = loadInvites();
  const inviteIdx = invites.findIndex((inv) => inv.code === renewCode && !inv.used && !isInviteExpired(inv));
  if (inviteIdx === -1) {
    return res.send(`
      <!DOCTYPE html>
      <html><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1">${THEME_STYLE}</head>
      <body style="display:flex; justify-content:center; align-items:center; height:100vh;">
        ${RADAR_BG}
        <div class="glass" style="padding:32px; text-align:center;">
          <p style="color:#ff3860;">인증코드가 올바르지 않거나 이미 사용됐어요.</p>
          <a href="/admin/renew" style="color:#E0399B;">다시 시도</a>
        </div>
      </body></html>
    `);
  }

  const users = loadUsers();
  const user = users[username];
  user.subscriptionType = 'period';
  user.subscriptionExpiresAt = addMonthsToTodayKST(1);
  saveUsers(users);

  invites[inviteIdx].used = true;
  invites[inviteIdx].usedBy = username;
  invites[inviteIdx].usedAt = new Date().toISOString();
  saveInvites(invites);

  logActivity(username, '구독 갱신', '인증코드: ' + renewCode + ' → ' + user.subscriptionExpiresAt + '까지');
  res.redirect('/admin');
});

app.post('/admin/invites/create', (req, res) => {
  if (!isLoggedIn(req)) return res.redirect('/admin/login');
  if (!isAdminUser(req)) return res.status(403).send('관리자만 초대 코드를 만들 수 있어요');
  const invites = loadInvites();
  const code = generateInviteCode();
  const validDays = parseInt(req.body.validDays, 10) || 7;
  invites.push({
    code, createdBy: getCurrentUser(req), createdAt: new Date().toISOString(),
    validUntil: addDaysToTodayKST(validDays),
    used: false, usedBy: null, usedAt: null
  });
  saveInvites(invites);
  logActivity(getCurrentUser(req), '초대 코드 발급', code + ` (${validDays}일 유효)`);
  res.redirect('/admin');
});

app.post('/admin/users/create', (req, res) => {
  if (!isLoggedIn(req)) return res.redirect('/admin/login');
  if (!isAdminUser(req)) return res.status(403).send('관리자만 사용자 계정을 만들 수 있어요');
  const { username, password, isAdmin, email } = req.body;
  const name = (username || '').trim();
  if (!name || !password) return res.status(400).send('아이디와 비밀번호를 입력해주세요');
  const users = loadUsers();
  if (users[name]) return res.status(400).send('이미 있는 아이디예요');
  users[name] = {
    password: hashPassword(password), isAdmin: isAdmin === 'on', youtubeId: '', email: (email || '').trim(),
    subscriptionType: 'period', subscriptionExpiresAt: addMonthsToTodayKST(1),
    createdAt: getTodayKST(), adminNote: ''
  };
  saveUsers(users);
  res.redirect('/admin');
});

app.post('/admin/users/delete', (req, res) => {
  if (!isLoggedIn(req)) return res.redirect('/admin/login');
  if (!isAdminUser(req)) return res.status(403).send('관리자만 사용자 계정을 삭제할 수 있어요');
  const { username } = req.body;
  if (username === getCurrentUser(req)) return res.status(400).send('본인 계정은 삭제할 수 없어요');
  const users = loadUsers();
  delete users[username];
  saveUsers(users);
  logActivity(getCurrentUser(req), '계정 삭제', username);
  res.redirect('/admin');
});

app.post('/admin/users/reset-password', (req, res) => {
  if (!isLoggedIn(req)) return res.redirect('/admin/login');
  if (!isAdminUser(req)) return res.status(403).send('관리자만 비밀번호를 초기화할 수 있어요');
  const { username } = req.body;
  const users = loadUsers();
  if (!users[username]) return res.status(404).send('사용자를 찾을 수 없어요');
  users[username].password = hashPassword('123456');
  saveUsers(users);
  logActivity(getCurrentUser(req), '비밀번호 초기화', username + ' → 123456');
  res.redirect('/admin');
});

app.post('/admin/users/set-subscription', (req, res) => {
  if (!isLoggedIn(req)) return res.redirect('/admin/login');
  if (!isAdminUser(req)) return res.status(403).send('관리자만 이용 기간을 설정할 수 있어요');
  const { username, type, expiresAt } = req.body;
  const users = loadUsers();
  if (!users[username]) return res.status(404).send('사용자를 찾을 수 없어요');

  if (type === 'lifetime') {
    users[username].subscriptionType = 'lifetime';
    users[username].subscriptionExpiresAt = '';
    logActivity(getCurrentUser(req), '이용기간 설정', username + ' → 평생이용');
  } else {
    users[username].subscriptionType = 'period';
    users[username].subscriptionExpiresAt = expiresAt || addMonthsToTodayKST(1);
    logActivity(getCurrentUser(req), '이용기간 설정', username + ' → ' + users[username].subscriptionExpiresAt + '까지');
  }
  saveUsers(users);
  res.redirect('/admin');
});

app.post('/admin/users/bulk-extend', (req, res) => {
  if (!isLoggedIn(req)) return res.redirect('/admin/login');
  if (!isAdminUser(req)) return res.status(403).send('관리자만 일괄 연장할 수 있어요');
  let usernames = req.body.usernames || [];
  if (!Array.isArray(usernames)) usernames = [usernames];
  const users = loadUsers();
  const newExpiry = addMonthsToTodayKST(1);
  usernames.forEach((username) => {
    if (users[username] && !users[username].isAdmin) {
      users[username].subscriptionType = 'period';
      users[username].subscriptionExpiresAt = newExpiry;
    }
  });
  saveUsers(users);
  logActivity(getCurrentUser(req), '일괄 이용기간 연장', usernames.join(', ') + ' → ' + newExpiry + '까지');
  res.redirect('/admin');
});

app.post('/admin/users/set-note', (req, res) => {
  if (!isLoggedIn(req)) return res.redirect('/admin/login');
  if (!isAdminUser(req)) return res.status(403).send('관리자만 메모를 남길 수 있어요');
  const { username, note } = req.body;
  const users = loadUsers();
  if (!users[username]) return res.status(404).send('사용자를 찾을 수 없어요');
  users[username].adminNote = (note || '').slice(0, 50);
  saveUsers(users);
  res.redirect('/admin');
});

app.post('/admin/api/verify-admin-password', (req, res) => {
  if (!isLoggedIn(req)) return res.status(401).json({ success: false, error: '로그인이 필요해요' });
  if (!isAdminUser(req)) return res.status(403).json({ success: false, error: '관리자만 볼 수 있어요' });
  const users = loadUsers();
  const me = users[getCurrentUser(req)];
  if (!me || !verifyPassword(req.body.password || '', me.password)) {
    return res.json({ success: false, error: '비밀번호가 틀렸어요' });
  }
  const details = {};
  for (const u in users) {
    details[u] = {
      email: users[u].email || '(없음)',
      referredBy: users[u].referredBy || '(없음)',
      realName: users[u].realName || '(없음)',
      nickname: users[u].nickname || '(없음)'
    };
  }
  res.json({ success: true, details });
});

app.post('/admin/settings/profile', (req, res) => {
  if (!isLoggedIn(req)) return res.redirect('/admin/login');
  const username = getCurrentUser(req);
  const { nickname, avatarUrl, realName } = req.body;
  const users = loadUsers();
  if (!users[username]) return res.redirect('/admin/login');
  users[username].nickname = (nickname || '').slice(0, 30);
  users[username].avatarUrl = avatarUrl || '';
  users[username].realName = (realName || '').slice(0, 30);
  saveUsers(users);
  res.redirect('/admin');
});

app.post('/admin/settings/disclosures', (req, res) => {
  if (!isLoggedIn(req)) return res.redirect('/admin/login');
  const username = getCurrentUser(req);
  const { coupang, toss, naver, olive } = req.body;
  const users = loadUsers();
  if (!users[username]) return res.redirect('/admin/login');
  users[username].disclosureTexts = {
    coupang: coupang || '', toss: toss || '', naver: naver || '', olive: olive || ''
  };
  saveUsers(users);
  res.redirect('/admin');
});

app.post('/admin/settings/password', (req, res) => {
  if (!isLoggedIn(req)) return res.redirect('/admin/login');
  const username = getCurrentUser(req);
  const { currentPassword, newPassword, newPasswordConfirm } = req.body;
  const users = loadUsers();
  const user = users[username];

  function fail(msg) {
    res.send(`
      <!DOCTYPE html>
      <html><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1">${THEME_STYLE}</head>
      <body style="display:flex; justify-content:center; align-items:center; height:100vh;">
        ${RADAR_BG}
        <div class="glass" style="padding:32px; text-align:center;">
          <p style="color:#ff3860;">${msg}</p>
          <a href="/admin">← 돌아가기</a>
        </div>
      </body></html>
    `);
  }

  if (!user || !verifyPassword(currentPassword || '', user.password)) return fail('현재 비밀번호가 틀렸어요.');
  if (!newPassword || newPassword.length < 4) return fail('새 비밀번호는 4자 이상으로 입력해주세요.');
  if (newPassword !== newPasswordConfirm) return fail('새 비밀번호가 서로 달라요.');

  user.password = hashPassword(newPassword);
  saveUsers(users);
  logActivity(username, '비밀번호 변경 (본인)', '');
  res.redirect('/admin');
});

// 개인 쿠팡 API 키 저장 (2차 비밀번호로 암호화 — 관리자도, 서버 파일만으로도 복호화 불가능)
app.post('/admin/settings/coupang-api/save', (req, res) => {
  if (!isLoggedIn(req)) return res.status(401).json({ success: false, error: '로그인이 필요해요' });
  const username = getCurrentUser(req);
  const { accessKey, secretKey, secondPassword } = req.body;
  if (!accessKey || !secretKey || !secondPassword) {
    return res.json({ success: false, error: 'Access Key, Secret Key, 2차 비밀번호를 모두 입력해주세요' });
  }
  if (secondPassword.length < 4) {
    return res.json({ success: false, error: '2차 비밀번호는 4자 이상으로 해주세요' });
  }
  const users = loadUsers();
  const user = users[username];
  if (!user) return res.status(401).json({ success: false, error: '로그인이 필요해요' });

  const trimmedAccess = accessKey.trim();
  const trimmedSecret = secretKey.trim();
  // 조회/수정용 (2차 비밀번호로만 열림)
  user.coupangKeyBlob = encryptCoupangKeys(secondPassword, trimmedAccess, trimmedSecret);
  // 사용(검색/자동변환)용 (서버가 비밀번호 입력 없이 바로 씀)
  user.coupangKeyServerBlob = encryptCoupangKeysServerSide(trimmedAccess, trimmedSecret);
  saveUsers(users);
  logActivity(username, '개인 쿠팡 API 키 등록/변경', '');
  res.json({ success: true });
});

// 2차 비밀번호로 내 쿠팡 API 키 "조회"만 함 (검색/자동변환 사용에는 영향 없음, 항상 바로 쓸 수 있어요)
app.post('/admin/settings/coupang-api/unlock', (req, res) => {
  if (!isLoggedIn(req)) return res.status(401).json({ success: false, error: '로그인이 필요해요' });
  const username = getCurrentUser(req);
  const users = loadUsers();
  const user = users[username];
  if (!user || !user.coupangKeyBlob) return res.json({ success: false, error: '등록된 키가 없어요' });

  const result = decryptCoupangKeys(req.body.secondPassword || '', user.coupangKeyBlob);
  if (!result) return res.json({ success: false, error: '2차 비밀번호가 틀렸어요' });

  res.json({ success: true, accessKey: result.accessKey, secretKey: result.secretKey });
});

app.post('/admin/settings/2fa/start', (req, res) => {
  if (!isLoggedIn(req)) return res.status(401).json({ success: false });
  const username = getCurrentUser(req);
  const users = loadUsers();
  const secret = generateTotpSecret();
  users[username].totpSecret = secret;
  users[username].totpEnabled = false;
  saveUsers(users);
  const otpauth = `otpauth://totp/${encodeURIComponent('반짝딜:' + username)}?secret=${secret}&issuer=${encodeURIComponent('반짝딜')}`;
  const qrUrl = `https://api.qrserver.com/v1/create-qr-code/?size=180x180&data=${encodeURIComponent(otpauth)}`;
  res.json({ success: true, secret, qrUrl });
});

app.post('/admin/settings/2fa/confirm', (req, res) => {
  if (!isLoggedIn(req)) return res.status(401).json({ success: false });
  const username = getCurrentUser(req);
  const users = loadUsers();
  const user = users[username];
  if (!user || !user.totpSecret) return res.json({ success: false, error: '먼저 설정을 시작해주세요' });
  if (!verifyTotpCode(user.totpSecret, req.body.code || '')) {
    return res.json({ success: false, error: '코드가 틀렸어요' });
  }
  user.totpEnabled = true;
  saveUsers(users);
  logActivity(username, '2FA 활성화', '');
  res.json({ success: true });
});

app.post('/admin/settings/2fa/disable', (req, res) => {
  if (!isLoggedIn(req)) return res.redirect('/admin/login');
  const username = getCurrentUser(req);
  const users = loadUsers();
  if (users[username]) {
    users[username].totpEnabled = false;
    users[username].totpSecret = '';
    saveUsers(users);
    logActivity(username, '2FA 비활성화', '');
  }
  res.redirect('/admin');
});

app.listen(PORT, () => {
  console.log(`서버가 켜졌어요: http://localhost:${PORT}`);
});
