// Optional load for a k6 runner (NOT run in the repository's checks: k6 is not installed there).
// The built-in monitor in range.py measures availability and p95 latency without k6; use this when you want
// k6's own thresholds against a running range:  k6 run -e HOST=svc-xxxx.range.test -e PORT=8441 k6_load.js
import http from 'k6/http';
import { check, sleep } from 'k6';

export const options = {
  vus: 5,
  duration: '30s',
  thresholds: { http_req_failed: ['rate<0.01'], http_req_duration: ['p(95)<250'] },
  hosts: { [`${__ENV.HOST}:${__ENV.PORT}`]: '127.0.0.1' },
};

export default function () {
  const res = http.get(`https://${__ENV.HOST}:${__ENV.PORT}/health`);
  check(res, { 'status is 200': (r) => r.status === 200 });
  sleep(0.2);
}
