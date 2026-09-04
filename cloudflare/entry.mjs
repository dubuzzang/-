import '../index.js';
import { DurableObject } from 'cloudflare:workers';
import { httpServerHandler } from 'cloudflare:node';

const appHandler = httpServerHandler({ port: 3000 });

function requiresCoordination(request) {
  if (request.method !== 'GET' && request.method !== 'HEAD') return true;
  const path = new URL(request.url).pathname;
  return /^\/r\/[^/]+\/go\/?$/i.test(path) || path === '/admin' || path.startsWith('/__cloudflare/');
}

export class RequestCoordinator extends DurableObject {
  constructor(context, env) {
    super(context, env);
    this.tail = Promise.resolve();
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

export default {
  fetch: coordinatedFetch,
  async scheduled(_controller, env, context) {
    const response = await coordinatedFetch(new Request('https://internal.invalid/__cloudflare/maintenance', {
      method: 'POST'
    }), env, context);
    if (!response.ok) throw new Error(`Maintenance failed with HTTP ${response.status}`);
    await response.arrayBuffer();
  }
};
