package idempotency

// claimScript atomically claims KEYS[1] for processing unless a value is
// already stored there, in which case that value is returned instead and
// nothing is written.
//
// Reused as the poll primitive too: once the original holder's reservation
// TTL lapses without a Save, the key simply expires, and the next caller's
// claim attempt succeeds and takes over — no separate cleanup path needed.
const claimScript = `

local existing = redis.call(
	"GET",
	KEYS[1]
)


if existing then

	return existing

end


redis.call(
	"SET",
	KEYS[1],
	ARGV[1],
	"EX",
	ARGV[2]
)


return ""

`
