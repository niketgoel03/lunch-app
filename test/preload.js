// TEST-ONLY preload: makes require('pg') resolve to an in-memory Postgres
// (pg-mem) so the real server can run end-to-end without a live database.
// Not used in production.
'use strict';
const Module = require('module');
const { newDb } = require('pg-mem');

const mem = newDb();
const pgAdapter = mem.adapters.createPg(); // { Pool, Client }

const orig = Module._load;
Module._load = function (request) {
  if (request === 'pg') return pgAdapter;
  return orig.apply(this, arguments);
};
