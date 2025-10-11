const request = require('supertest');
const { app, start } = require('../server');

let server;

beforeAll(async () => {
  // Start server in test mode (will use in-memory fallback since no DB in CI)
  process.env.PORT = 5001;
  await start();
});

afterAll(() => {
  // nothing to cleanup; server created by start() will keep running
});

describe('Auth flow (smoke)', () => {
  test('register -> login -> me', async () => {
    const email = `test${Date.now()}@example.com`;
    const password = 'TestPass123';

    const reg = await request(app).post('/register').send({ email, password });
    expect(reg.status).toBe(201);
    expect(reg.body.success).toBe(true);

    const login = await request(app).post('/login').send({ email, password });
    expect(login.status).toBe(200);
    expect(login.body.success).toBe(true);

    const agent = request.agent(app);
    await agent.post('/login').send({ email, password });
    const me = await agent.get('/me');
    expect(me.body.loggedIn).toBeDefined();
  }, 10000);
});
