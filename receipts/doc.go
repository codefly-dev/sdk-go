// Package receipts answers the one question a Runnable operation's recovery
// asks its owner: what did effect X commit?
//
// The runtime installs a SERVICE operation with RECOVERY_RECEIPT. After an
// inconclusive attempt it does not retry; it asks the owner for the effect's
// receipt, and "no receipt" is inconclusive rather than permission to run the
// effect again. A plain unary method has no such half, so this package is it:
// a store the handler writes its receipt to, and an interceptor that replays a
// receipt it already holds instead of calling the handler a second time.
//
// # The one rule
//
// Record the receipt inside the transaction that commits the effect. A receipt
// written after the commit leaves a window in which the effect exists and the
// receipt does not, and a recovery landing in that window reads "no receipt"
// for an effect that already happened — which is the one outcome
// RECOVERY_RECEIPT exists to prevent. That is why Record takes a Tx: the SDK
// cannot open the handler's transaction for it, so the handler passes the very
// transaction it is about to commit.
//
//	tx, err := db.BeginTx(ctx, nil)
//	...
//	if err := receipts.Record(ctx, store, tx, response); err != nil {
//	        return nil, err
//	}
//	return response, tx.Commit()
//
// The interceptor does everything else: it requires the effect id, fingerprints
// the request, replays a matching receipt, refuses an effect id reused for a
// different request, and serializes concurrent first attempts so exactly one
// handler runs.
//
// # Retention
//
// A swept receipt makes a later lookup report no receipt, which a recovery
// treats as inconclusive rather than as "the effect did not happen". Retention
// must therefore exceed the runtime's maximum recovery horizon: sweeping at
// DefaultRetention is safe only while that horizon stays shorter than it.
package receipts
