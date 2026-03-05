import http from 'k6/http';
import { check } from 'k6';
import { Counter, Rate, Trend } from 'k6/metrics';

const baseUrl = (__ENV.AUTH_BASE_URL || 'http://127.0.0.1:8080').replace(/\/$/, '');
const email = __ENV.AUTH_PERF_EMAIL;
const password = __ENV.AUTH_PERF_PASSWORD;
const mode = __ENV.AUTH_PERF_MODE || 'load';

const ratePerSecond = Number(__ENV.AUTH_PERF_RATE || '200');
const duration = __ENV.AUTH_PERF_DURATION || (mode === 'soak' ? '30m' : '3m');
const preAllocatedVus = Number(__ENV.AUTH_PERF_PREALLOCATED_VUS || (mode === 'soak' ? '100' : '200'));
const maxVus = Number(__ENV.AUTH_PERF_MAX_VUS || (mode === 'soak' ? '300' : '600'));

const loginDuration = new Trend('login_duration', true);
const refreshDuration = new Trend('refresh_duration', true);
const meDuration = new Trend('me_duration', true);
const loginRequests = new Counter('login_requests_total');
const refreshRequests = new Counter('refresh_requests_total');
const meRequests = new Counter('me_requests_total');
const authFlowErrorRate = new Rate('auth_flow_error_rate');

export const options = {
  discardResponseBodies: true,
  insecureSkipTLSVerify: __ENV.AUTH_PERF_INSECURE_TLS === 'true',
  scenarios: {
    auth_flow: {
      executor: 'constant-arrival-rate',
      rate: ratePerSecond,
      timeUnit: '1s',
      duration,
      preAllocatedVUs: preAllocatedVus,
      maxVUs: maxVus,
    },
  },
};

function parseJson(response) {
  try {
    return response.json();
  } catch (_) {
    return null;
  }
}

function authHeaders(accessToken) {
  return {
    Authorization: `Bearer ${accessToken}`,
    'x-trace-id': `perf-${__VU}-${__ITER}`,
  };
}

export function setup() {
  if (!email || !password) {
    throw new Error('AUTH_PERF_EMAIL and AUTH_PERF_PASSWORD are required');
  }

  return { email, password };
}

export default function (data) {
  let hasError = false;
  const requestHeaders = {
    headers: {
      'Content-Type': 'application/json',
      'x-trace-id': `perf-${__VU}-${__ITER}`,
    },
  };

  const loginResponse = http.post(
    `${baseUrl}/v1/auth/login`,
    JSON.stringify({
      email: data.email,
      password: data.password,
      device_info: `perf-vu-${__VU}`,
    }),
    requestHeaders,
  );
  loginDuration.add(loginResponse.timings.duration);
  loginRequests.add(1);

  const loginPayload = parseJson(loginResponse);
  const loginOk = check(loginResponse, {
    'login status is 200': (r) => r.status === 200,
    'login returns access token': () =>
      Boolean(loginPayload && !loginPayload.mfa_required && loginPayload.access_token),
    'login returns refresh token': () =>
      Boolean(loginPayload && !loginPayload.mfa_required && loginPayload.refresh_token),
  });

  if (!loginOk || !loginPayload || !loginPayload.access_token || !loginPayload.refresh_token) {
    hasError = true;
    authFlowErrorRate.add(hasError);
    return;
  }

  const meBeforeRefresh = http.get(`${baseUrl}/v1/auth/me`, {
    headers: authHeaders(loginPayload.access_token),
  });
  meDuration.add(meBeforeRefresh.timings.duration);
  meRequests.add(1);

  const meBeforeRefreshOk = check(meBeforeRefresh, {
    'me before refresh status is 200': (r) => r.status === 200,
  });
  if (!meBeforeRefreshOk) {
    hasError = true;
  }

  const refreshResponse = http.post(
    `${baseUrl}/v1/auth/token/refresh`,
    JSON.stringify({ refresh_token: loginPayload.refresh_token }),
    requestHeaders,
  );
  refreshDuration.add(refreshResponse.timings.duration);
  refreshRequests.add(1);

  const refreshPayload = parseJson(refreshResponse);
  const refreshOk = check(refreshResponse, {
    'refresh status is 200': (r) => r.status === 200,
    'refresh returns new access token': () => Boolean(refreshPayload && refreshPayload.access_token),
    'refresh returns new refresh token': () => Boolean(refreshPayload && refreshPayload.refresh_token),
  });
  if (!refreshOk || !refreshPayload || !refreshPayload.access_token) {
    hasError = true;
    authFlowErrorRate.add(hasError);
    return;
  }

  const meAfterRefresh = http.get(`${baseUrl}/v1/auth/me`, {
    headers: authHeaders(refreshPayload.access_token),
  });
  meDuration.add(meAfterRefresh.timings.duration);
  meRequests.add(1);

  const meAfterRefreshOk = check(meAfterRefresh, {
    'me after refresh status is 200': (r) => r.status === 200,
  });
  if (!meAfterRefreshOk) {
    hasError = true;
  }

  authFlowErrorRate.add(hasError);
}
