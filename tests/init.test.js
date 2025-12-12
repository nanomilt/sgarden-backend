import http from "node:http";

import test from "ava";
import got from "got";

import app from "../server.js";

// test("Test passes", (t) => {
// 	t.pass();
// });

// test("Test fails", (t) => {
// 	t.fail();
// });

// test("Test throws", (t) => {
//     t.throws(() => {
// 	    throw new Error("Test failed");
//     });
// });

// const addNumbers = (a,b) => a + b;

// test('Add numbers', t => {
//     t.is(addNumbers(1,2), 3);
//     t.is(addNumbers(3,5), 8);
//     t.is(addNumbers(-1,2), 1);
//     t.is(addNumbers(0,0), 0);
//     t.is(addNumbers(0,2), 2);
//     t.is(addNumbers("1", "2"), "12");
//     t.is(addNumbers("1", 2), "12");
//     t.is(addNumbers(undefined, 2), NaN);
//     t.is(addNumbers(), NaN);
// });

// test('Async', async t => {
//     const res = Promise.resolve('test');
//     t.is(await res, 'test');
// });

test.before(async (t) => {
	t.context.server = http.createServer(app);
    const server = t.context.server.listen();
    const { port } = server.address();
	t.context.got = got.extend({ responseType: "json", prefixUrl: `http://localhost:${port}` });
});

test.after.always((t) => {
	t.context.server.close();
});

test("GET /api returns correct response and status code", async (t) => {
	const { body, statusCode } = await t.context.got("api");
	t.is(body.message, "It works!");
	t.is(statusCode, 200);
});
