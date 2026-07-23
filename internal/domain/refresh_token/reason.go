package refresh_token

type RevokeReason string

const (
	RevokeReasonLogout RevokeReason = "LOGOUT"

	RevokeReasonReplay RevokeReason = "REPLAY_DETECTED"

	RevokeReasonExpired RevokeReason = "EXPIRED"
)
