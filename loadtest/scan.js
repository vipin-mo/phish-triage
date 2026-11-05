// Load test of the live scan endpoint (Phase 7); `make load-test` runs it and writes reports/load_test.md.
//
// Every request is the same hand-made, harmless newsletter with a unique header, so each one is a new scan (not a
// stored verdict) and no real email is ever sent. It runs under its own API key (owner `loadtest`, left out of the
// real-use report). Four stages at fixed request rates, so the number of requests is capped whatever the answers do
// (the first run had no cap: refused requests came back in milliseconds and each user looped as fast as it could).
// At most 30 + 60 + 150 + 300 = 540 requests:
//   r1  - 1 a second for 30 s: under every limit
//   r2  - 2 a second: 60 in 30 s, up to the 60-a-minute key limit
//   r5  - 5 a second: at API Gateway's throttle
//   r10 - 10 a second: past it
// The stages start a little over a minute apart, so each meets a fresh per-minute key count (per calendar minute, so
// a stage that spans two minutes may get up to 120 answers). Past a limit the answer should be a fast refusal (429),
// never a failure or a pile-up of functions; each 429 is counted by which limit said it.
import http from 'k6/http';
import { Counter } from 'k6/metrics';

const refusedByGateway = new Counter('refused_by_gateway'); // API Gateway's throttle, before the function runs
const refusedByKeyLimit = new Counter('refused_by_key_limit'); // the API's 60 a minute per key, in the function

const API = __ENV.API_URL;
const KEY = __ENV.API_KEY;
const EMAIL = `From: Campus Garden Club <news@garden.example>
To: me@example.com
Subject: This week at the community garden
MIME-Version: 1.0
Content-Type: text/plain; charset=UTF-8

Hello gardeners,

The tomatoes are nearly ready and the compost bins were turned on Saturday. Volunteers meet on Thursday at five
near the greenhouse; bring gloves if you have them. Seeds for the winter beds are in the shed, labelled by row.

Thanks to everyone who helped paint the new benches last weekend. See you at the garden.

The Garden Club
`;

export const options = {
  scenarios: {
    r1: { executor: 'constant-arrival-rate', rate: 1, duration: '30s', preAllocatedVUs: 5, maxVUs: 20, startTime: '0s' },
    r2: { executor: 'constant-arrival-rate', rate: 2, duration: '30s', preAllocatedVUs: 5, maxVUs: 20, startTime: '65s' },
    r5: { executor: 'constant-arrival-rate', rate: 5, duration: '30s', preAllocatedVUs: 10, maxVUs: 20, startTime: '130s' },
    r10: { executor: 'constant-arrival-rate', rate: 10, duration: '30s', preAllocatedVUs: 20, maxVUs: 40, startTime: '195s' },
  },
};

export default function () {
  const id = `${__VU}-${__ITER}-${Date.now()}`;
  const response = http.post(`${API}/v1/scan`, `X-Load-Test: ${id}\n${EMAIL}`, {
    headers: { 'x-api-key': KEY, 'content-type': 'message/rfc822' },
    timeout: '40s',
  });
  if (response.status === 429) {
    (String(response.body).includes('try again in a minute') ? refusedByKeyLimit : refusedByGateway).add(1);
  }
}
