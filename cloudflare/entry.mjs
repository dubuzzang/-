import '../index.js';
import { DurableObject } from 'cloudflare:workers';
import { httpServerHandler } from 'cloudflare:node';
import clickCounter from './click-counter.js';

const { cleanClickEvent, clickResponse, countryName, flushClickBatch, todayKST } = clickCounter;
const appHandler = httpServerHandler({ port: 3000 });

// 클릭은 대기열에 쌓였다가 이만큼 뒤에 한꺼번에 저장됨 (대시보드 숫자도 그만큼 늦게 바뀜)
const CLICK_FLUSH_DELAY_MS = 2000;
const CLICK_FLUSH_BATCH = 1000;
// 짧은 링크 이동에 쓰는 links.json 사본을 Worker마다 이 시간 동안 재사용
const LINKS_CACHE_MS = 5000;
const CLICK_PATH = /^\/r\/([^/]+)\/go\/?$/i;

function requiresCoordination(request) {
  if (request.method !== 'GET' && request.method !== 'HEAD') return true;
  const path = new URL(request.url).pathname;
  return CLICK_PATH.test(path) || path === '/admin' || path.startsWith('/__cloudflare/');
}

export class RequestCoordinator extends DurableObject {
  constructor(context, env) {
    super(context, env);
    this.tail = Promise.resolve();
    this.ctx.storage.sql.exec(
      'CREATE TABLE IF NOT EXISTS pending_clicks (id INTEGER PRIMARY KEY AUTOINCREMENT, code TEXT NOT NULL, date TEXT NOT NULL, ip TEXT NOT NULL, source TEXT NOT NULL, country TEXT NOT NULL)'
    );
  }

  // 짧은 링크 방문이 기다리지 않고 부르는 RPC. SQLite에 한 줄 넣기만 함
  async recordClick(event) {
    const click = cleanClickEvent(event);
    if (!click) return;
    this.ctx.storage.sql.exec(
      'INSERT INTO pending_clicks (code, date, ip, source, country) VALUES (?, ?, ?, ?, ?)',
      click.code, click.date, click.ip, click.source, click.country
    );
    if ((await this.ctx.storage.getAlarm()) === null) await this.ctx.storage.setAlarm(Date.now() + CLICK_FLUSH_DELAY_MS);
  }

  // 쌓인 클릭을 다른 저장 요청과 같은 순서 줄에서 반영해서, 링크 수정 · 삭제와 서로 덮어쓰지 않음.
  // 실패하면 줄은 그대로 남고 알람이 다시 시도함
  async alarm() {
    const run = this.tail.then(async () => {
      const rows = this.ctx.storage.sql
        .exec('SELECT id, code, date, ip, source, country FROM pending_clicks ORDER BY id LIMIT ?', CLICK_FLUSH_BATCH)
        .toArray();
      if (!rows.length) return;
      await flushClickBatch(this.env.DATA, rows);
      this.ctx.storage.sql.exec('DELETE FROM pending_clicks WHERE id <= ?', rows[rows.length - 1].id);
      if (rows.length === CLICK_FLUSH_BATCH) await this.ctx.storage.setAlarm(Date.now());
    });
    this.tail = run.then(() => undefined, () => undefined);
    await run;
  }

  fetch(request) {
    const executionContext = {
      waitUntil: (promise) => this.ctx.waitUntil(promise),
      passThroughOnException() {},
      props: {}
    };
    const response = this.tail.then(() => appHandler.fetch(request, this.env, executionContext));
    this.tail = response.then(() => undefined, () => undefined);
    return response;
  }
}

function coordinatedFetch(request, env, context) {
  if (!requiresCoordination(request)) return appHandler.fetch(request, env, context);
  return env.REQUEST_COORDINATOR.getByName('global').fetch(request);
}

// ===== 짧은 링크 이동 빠른 경로 =====
// 예전엔 클릭마다 순서 줄에 서서 저장 문서 6개를 읽고 2개를 다 쓴 뒤에야 이동했음
// (동시에 20명이 누르면 마지막 사람은 1.6초 대기). 이제 사본으로 바로 이동시키고 클릭 수만 대기열로 보냄
let cachedLinks = null;
let cachedAt = 0;
let loadingLinks = null;

function loadLinksCopy(env) {
  if (!loadingLinks) {
    loadingLinks = env.DATA.get('data/links.json')
      .then(async (object) => {
        cachedLinks = object ? JSON.parse(await object.text()) : {};
        cachedAt = Date.now();
        return cachedLinks;
      })
      .finally(() => { loadingLinks = null; });
  }
  return loadingLinks;
}

async function linksForClick(env, code) {
  let links = cachedLinks && Date.now() - cachedAt < LINKS_CACHE_MS ? cachedLinks : await loadLinksCopy(env);
  // 방금 만든 링크는 아직 사본에 없을 수 있어서, 1초에 한 번까지는 다시 읽어봄
  if (!Object.hasOwn(links, code) && Date.now() - cachedAt > 1000) links = await loadLinksCopy(env);
  return links;
}

async function answerClick(request, env, context) {
  if (request.method !== 'GET' && request.method !== 'HEAD') return null;
  const url = new URL(request.url);
  const match = CLICK_PATH.exec(url.pathname);
  if (!match) return null;
  let code;
  try {
    code = decodeURIComponent(match[1]);
  } catch (_error) {
    return null;
  }
  const today = todayKST();
  const answer = clickResponse(await linksForClick(env, code), code, today);
  if (!answer) return null;
  if (answer.status !== 302) {
    return new Response(answer.body, { status: answer.status, headers: { 'Content-Type': 'text/html; charset=utf-8' } });
  }
  // HEAD(미리보기 확인 등)는 클릭으로 세지 않음. IP는 방문자가 바꿀 수 없는 cf-connecting-ip만 씀
  if (request.method === 'GET') {
    const event = cleanClickEvent({
      code,
      date: today,
      ip: request.headers.get('cf-connecting-ip') || '',
      source: url.searchParams.get('src'),
      country: countryName(request.headers.get('cf-ipcountry'))
    });
    if (event) {
      context.waitUntil(
        env.REQUEST_COORDINATOR.getByName('global').recordClick(event).catch((error) => {
          console.error(JSON.stringify({ event: 'click-queue-failed', message: String((error && error.message) || error).slice(0, 200) }));
        })
      );
    }
  }
  return new Response(null, { status: 302, headers: { Location: answer.location } });
}

export default {
  async fetch(request, env, context) {
    try {
      const response = await answerClick(request, env, context);
      if (response) return response;
    } catch (error) {
      console.error(JSON.stringify({ event: 'click-fast-path-failed', message: String((error && error.message) || error).slice(0, 200) }));
    }
    return coordinatedFetch(request, env, context);
  },
  async scheduled(_controller, env, context) {
    const response = await coordinatedFetch(new Request('https://internal.invalid/__cloudflare/maintenance', {
      method: 'POST'
    }), env, context);
    if (!response.ok) throw new Error(`Maintenance failed with HTTP ${response.status}`);
    await response.arrayBuffer();
  }
};
