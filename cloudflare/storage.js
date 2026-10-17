'use strict';

const fs = require('node:fs');
const { AsyncLocalStorage } = require('node:async_hooks');

const isCloudflare = process.env.CLOUDFLARE_RUNTIME === 'true';
const requestStorage = new AsyncLocalStorage();
let workersApi;

function api() {
  if (!workersApi) workersApi = require('./runtime.mjs');
  return workersApi;
}

function clone(value) {
  return JSON.parse(JSON.stringify(value));
}

function getBinding(name, fallback = '') {
  if (!isCloudflare) return fallback;
  const value = api().env[name];
  return value === undefined || value === null ? fallback : value;
}

// documentsFor(req): 그 요청에 필요한 문서 이름 목록 (null이면 전부). 안 읽은 문서는 읽기·쓰기 모두 오류로 막아서
// 빈 문서로 덮어쓰는 일이 없게 함. 기본값이 함수면 R2에 그 문서가 없을 때만 부름 (예: 관리자 비밀번호 해시는 계산이 무거움)
function jsonMiddleware(defaultsFactory, documentsFor) {
  if (!isCloudflare) return (_req, _res, next) => next();

  return async (_req, res, next) => {
    try {
      const defaults = typeof defaultsFactory === 'function' ? defaultsFactory() : defaultsFactory;
      const needed = typeof documentsFor === 'function' ? documentsFor(_req) : null;
      const names = Object.keys(defaults).filter((name) => !needed || needed.includes(name));
      const entries = await Promise.all(names.map(async (name) => {
        const fallback = defaults[name];
        const object = await api().env.DATA.get(`data/${name}.json`);
        if (!object) return [name, clone(typeof fallback === 'function' ? fallback() : fallback)];
        try {
          return [name, JSON.parse(await object.text())];
        } catch (error) {
          throw new Error(`Cloudflare R2의 data/${name}.json을 읽을 수 없습니다: ${error.message}`);
        }
      }));

      const state = { documents: Object.fromEntries(entries), loaded: new Set(names), writes: new Map() };
      const originalEnd = res.end.bind(res);
      let ending = false;

      // A mutating response is not released until every R2 write queued by the
      // Express handler has finished. The coordinator can therefore safely let
      // the next write request read the newly committed snapshot.
      res.end = function (...args) {
        if (ending) return res;
        ending = true;
        const writes = Promise.all([...state.writes.values()]);
        api().waitUntil(writes);
        writes.then(
          () => originalEnd(...args),
          () => {
            if (!res.headersSent) {
              res.statusCode = 500;
              res.removeHeader('Content-Length');
              res.setHeader('Content-Type', 'text/plain; charset=utf-8');
              return originalEnd('Cloudflare storage write failed');
            }
            return originalEnd(...args);
          }
        );
        return res;
      };

      requestStorage.run(state, next);
    } catch (error) {
      next(error);
    }
  };
}

function readJson(name, filePath, fallback) {
  if (!isCloudflare) {
    try {
      return JSON.parse(fs.readFileSync(filePath, 'utf8'));
    } catch (_error) {
      return clone(fallback);
    }
  }

  const state = requestStorage.getStore();
  if (!state) throw new Error(`Cloudflare 요청 저장소가 준비되기 전에 ${name}을 읽으려고 했습니다.`);
  if (!state.loaded.has(name)) throw new Error(`이 요청에서는 ${name} 문서를 불러오지 않았습니다.`);
  return clone(state.documents[name] === undefined ? fallback : state.documents[name]);
}

function writeJson(name, filePath, value) {
  if (!isCloudflare) {
    fs.writeFileSync(filePath, JSON.stringify(value, null, 2));
    return;
  }

  const state = requestStorage.getStore();
  if (!state) throw new Error(`Cloudflare 요청 저장소가 준비되기 전에 ${name}을 쓰려고 했습니다.`);
  if (!state.loaded.has(name)) throw new Error(`이 요청에서는 ${name} 문서를 불러오지 않아서 쓸 수 없습니다.`);
  state.documents[name] = clone(value);

  const previous = state.writes.get(name) || Promise.resolve();
  const write = previous.catch(() => {}).then(() => api().env.DATA.put(
    `data/${name}.json`,
    JSON.stringify(value, null, 2),
    { httpMetadata: { contentType: 'application/json; charset=utf-8' } }
  ));
  state.writes.set(name, write);
  api().waitUntil(write);
}

async function putObject(key, value, contentType) {
  if (!isCloudflare) throw new Error('putObject는 Cloudflare 런타임에서만 사용할 수 있습니다.');
  await api().env.DATA.put(key, value, {
    httpMetadata: contentType ? { contentType } : undefined
  });
}

async function getObject(key) {
  if (!isCloudflare) return null;
  return api().env.DATA.get(key);
}

module.exports = {
  getBinding,
  getObject,
  isCloudflare,
  jsonMiddleware,
  putObject,
  readJson,
  writeJson
};
