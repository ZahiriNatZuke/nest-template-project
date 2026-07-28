/**
 * bcrypt work factor, shared by everything that hashes a secret.
 *
 * It used to be written inline as `bcrypt.genSaltSync(16)` in the user,
 * password and api-key services — 16 in two of them and 12 in the third, with
 * nothing recording why they differed. A cost of 16 measures around three
 * seconds per hash on ordinary hardware, and it is paid on registration, on
 * every password change and on every reset. bcrypt's async calls run on
 * libuv's threadpool, four threads wide by default, so a handful of concurrent
 * sign-ups starves every other user of it — login included, since verifying a
 * password uses the same pool.
 *
 * 12 is the upper end of OWASP's recommendation and what api-key.service
 * already used. Raising it later is safe and needs no migration: the cost is
 * encoded in each hash, so `bcrypt.compare` reads it from the stored value and
 * old hashes keep verifying.
 *
 * The unit suites mock bcrypt, so no test would have caught the old value —
 * only measuring it does.
 */
export const BCRYPT_COST = 12;
