// Load against a RUNNING range (process or container mode), with k6's own thresholds. The range's monitor measures
// availability and p95 latency by itself; this is the second, independent source of the same kind of number.
// The certificate chain AND the host name are verified, so the range CA must be trusted by the k6 process:
//   SSL_CERT_FILE=state/certs/ca.crt k6 run -e HOST=svc-xxxx.range.test -e PORT=18441 k6_load.js
// (HOST: `make` prints it, `python3 cfr_range.py host`; PORT: state/ports.json). Run in CI by .github/workflows/cfr-docker.yml
// through the grafana/k6 container with --network host.
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
