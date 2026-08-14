package user

import "strings"

// canonicalizationRule describes how a specific email provider treats
// address variations as equivalent, so registration and login can collapse
// them to one identity instead of treating each variation as a separate
// account that happens to deliver to the same mailbox.
//
// This is deliberately per-domain, not a universal rule applied to every
// address. Only a handful of providers document that dots or a "+tag" in
// the local part are ignored on delivery; assuming that for an arbitrary
// domain would be a correctness bug, not a hardening — e.g. many
// companies hand out "first.last@company.com" where the dot is a real,
// meaningful separator between two different mailboxes, not decoration.
// A rule only belongs in the table below if the provider itself
// documents the equivalence — do not add one on assumption.
type canonicalizationRule struct {

	// canonicalDomain is what the domain part becomes after
	// normalization. Lets an aliased domain (e.g. Google's old
	// googlemail.com) collapse to the same canonical address its modern
	// equivalent produces.
	canonicalDomain string

	// stripDots removes '.' from the local part before the '@'.
	//
	// Gmail: "b.aditya@gmail.com" and "baditya@gmail.com" are the same
	// mailbox.
	stripDots bool

	// stripPlusTag truncates the local part at the first '+', discarding
	// everything from there to the '@'.
	//
	// Widely used for inbox filtering without provisioning a new mailbox
	// (e.g. "baditya+newsletters@gmail.com"). Support for this convention
	// varies by provider — it is listed per-domain below rather than
	// assumed, same as stripDots.
	stripPlusTag bool
}

// canonicalizationRules is keyed by the domain exactly as it appears in
// the address (lowercased), before normalization — so an aliased domain
// gets its own entry pointing at the canonical domain its equivalent
// uses.
//
// To extend this to another provider: add an entry (or two, for a domain
// alias) here, after confirming the two rule fields against that
// provider's own documentation — do not copy Gmail's rule wholesale.
// Outlook and iCloud, for example, both support "+tag" addressing but
// neither ignores dots, so for either of them stripDots must stay false
// even though stripPlusTag would be true.
var canonicalizationRules = map[string]canonicalizationRule{

	"gmail.com": {
		canonicalDomain: "gmail.com",
		stripDots:       true,
		stripPlusTag:    true,
	},

	// Google's original signup domain (notably for early UK accounts,
	// pre-2005). Still valid, still delivers to the same inbox as the
	// gmail.com form of the same address.
	"googlemail.com": {
		canonicalDomain: "gmail.com",
		stripDots:       true,
		stripPlusTag:    true,
	},
}

// NormalizeEmail canonicalizes an email address so that every equivalent
// way of writing it — casing, surrounding whitespace, and, for a known
// provider, dots or a "+tag" in the local part — maps to the same stored
// value.
//
// Used identically by registration (so one mailbox can't back two
// accounts by varying dots or a tag) and login (so a user can
// authenticate with any variation they registered a different one
// under) — both must call this, or the two endpoints silently disagree
// about what "the same email" means.
//
// A domain with no rule in the table is only lowercased and trimmed: the
// address is left exactly as the user wrote it, since no documented
// equivalence exists to collapse it against.
func NormalizeEmail(
	email string,
) string {

	email =
		strings.ToLower(
			strings.TrimSpace(
				email,
			),
		)

	at := strings.LastIndex(email, "@")

	if at < 0 {
		return email
	}

	local := email[:at]

	domain := email[at+1:]

	rule, ok := canonicalizationRules[domain]

	if !ok {
		return email
	}

	if rule.stripPlusTag {

		if plus := strings.Index(local, "+"); plus >= 0 {
			local = local[:plus]
		}
	}

	if rule.stripDots {

		local = strings.ReplaceAll(local, ".", "")
	}

	return local + "@" + rule.canonicalDomain
}
