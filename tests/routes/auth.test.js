/**
 * tests/routes/auth.test.js
 *
 * Unit test for one endpoint in routes/auth.js: POST /api/auth/signup
 *
 * Run: npx jest
 */

process.env.NODE_ENV = 'test';

const request = require('supertest');
const express = require('express');
const cookieParser = require('cookie-parser');

// Mock dependencies used by routes/auth.js so tests don't require a real DB or JWT secrets
jest.mock('../../src/models/User', () => ({
    findOne: jest.fn(),
    create: jest.fn(),
}));

jest.mock('../../src/utils/jwt', () => ({
    signAccess: jest.fn(() => 'access.token.mock'),
    signRefresh: jest.fn(() => 'refresh.token.mock'),
    verifyRefresh: jest.fn(),
}));

jest.mock('bcrypt', () => ({
    hash: jest.fn(() => Promise.resolve('hashed.password.mock')),
    compare: jest.fn(() => Promise.resolve(true)),
}));

const User = require('../../src/models/User');
const { signAccess, signRefresh } = require('../../src/utils/jwt');

// IMPORTANT: require the router AFTER mocks
const authRouter = require('../../src/routes/auth.js');

function makeApp() {
    const app = express();
    app.use(express.json());
    app.use(cookieParser());
    app.use('/api/auth', authRouter);
    return app;
}

function makeAppWithErrorHandler() {
    const app = makeApp();
    app.use((err, req, res, next) => {
        res.status(500).json({ error: 'server error' });
    });
    return app;
}

describe('POST /api/auth/signup', () => {
    beforeEach(() => {
        jest.clearAllMocks();
    });

    test('creates a user and returns minimal profile + sets auth cookies', async () => {
        // Arrange
        User.findOne.mockResolvedValue(null);
        User.create.mockResolvedValue({
            _id: '697ff7f980b9586401ccc6ce',
            name: 'Dhwani',
            username: 'Dhwani',
            email: 'ddobariya@gmail.com',
            passwordHash: 'hashed.password.mock',
        });

        const app = makeApp();

        // Act
        const res = await request(app)
            .post('/api/auth/signup')
            .send({
                name: 'Dhwani',
                username: 'Dhwani',
                email: 'ddobariya@gmail.com',
                password: '123456',
            });

        // Assert
        expect([200, 201]).toContain(res.status);
        expect(res.body).toEqual({
            id: '697ff7f980b9586401ccc6ce',
            name: 'Dhwani',
            username: 'Dhwani',
            email: 'ddobariya@gmail.com',
        });

        // Tokens should be signed & stored in cookies (not returned in body)
        expect(signAccess).toHaveBeenCalledTimes(1);
        expect(signRefresh).toHaveBeenCalledTimes(1);
        expect(res.body.accessToken).toBeUndefined();
        expect(res.body.refreshToken).toBeUndefined();

        // Cookie headers
        const setCookie = res.headers['set-cookie'] || [];
        expect(setCookie.join(';')).toContain('accessToken=');
        expect(setCookie.join(';')).toContain('refreshToken=');
        expect(setCookie.join(';')).toMatch(/HttpOnly/i);
    });

    test('returns 400 when required fields are missing', async () => {
        const app = makeApp();

        const res = await request(app)
            .post('/api/auth/signup')
            .send({
                name: 'Dhwani',
                email: 'ddobariya@gmail.com',
                password: '123456',
                // username missing
            });

        expect(res.status).toBe(400);
        expect(res.body).toEqual({ error: 'All fields are required' });
    });

    test('returns 409 when mongo duplicate key error occurs (err.code === 11000)', async () => {
        // Arrange: let it pass "exists" check
        User.findOne.mockResolvedValue(null);

        // Force the catch block with duplicate key code
        User.create.mockRejectedValue({ code: 11000 });

        const app = makeApp();

        // Act
        const res = await request(app)
            .post('/api/auth/signup')
            .send({
                name: 'Dhwani',
                username: 'Dhwani',
                email: 'ddobariya@gmail.com',
                password: '123456',
            });

        // Assert
        expect(res.status).toBe(409);
        expect(res.body).toEqual({ error: 'Email or username already taken' });
    });

    test('calls next(err) for non-duplicate errors', async () => {
        User.findOne.mockResolvedValue(null);
        User.create.mockRejectedValue(new Error('boom'));

        const app = makeAppWithErrorHandler();

        const res = await request(app)
            .post('/api/auth/signup')
            .send({
                name: 'Dhwani',
                username: 'Dhwani',
                email: 'ddobariya@gmail.com',
                password: '123456',
            });

        expect(res.status).toBe(500);
        expect(res.body).toEqual({ error: 'server error' });
    });
});
