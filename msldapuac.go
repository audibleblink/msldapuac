package msldapuac

import (
	"github.com/audibleblink/bamflags"
)

const (
	script                     = 1 << iota // 1
	accountdisable                         // 2
	_                                      // noop
	homedirRequired                        // 8
	lockout                                // 16
	passwdNotReqd                          // 32
	passwdCantChange                       // 64
	encryptedTextPwdAllowed                // 128
	tempDuplicateAccount                   // 256
	normalAccount                          // 512
	_                                      // noop
	interdomainTrustAccount                // 2048
	workstationTrustAccount                // 4096
	serverTrustAccount                     // 8192
	_                                      // noop
	_                                      // noop
	dontExpirePassword                     // 65536
	mnsLogonAccount                        // 131072
	smartcardRequired                      // 262144
	trustedForDelegation                   // 524288
	notDelegated                           // 1048576
	useDesKeyOnly                          // 2097152
	dontReqPreauth                         // 4194304
	passwordExpired                        // 8388608
	trustedToAuthForDelegation             // 16777216
	_                                      // noop
	partialSecretsAccount                  // 67108864
)

// PropertyMap holds the Microsoft-defined values for all possible flags
// in the UserAccountControl LDAP field
//
// https://support.microsoft.com/en-us/help/305144
var PropertyMap = map[int]string{
	script:                     "SCRIPT",
	accountdisable:             "ACCOUNTDISABLE",
	homedirRequired:            "HOMEDIR_REQUIRED",
	lockout:                    "LOCKOUT",
	passwdNotReqd:              "PASSWD_NOTREQD",
	passwdCantChange:           "PASSWD_CANT_CHANGE",
	encryptedTextPwdAllowed:    "ENCRYPTED_TEXT_PWD_ALLOWED",
	tempDuplicateAccount:       "TEMP_DUPLICATE_ACCOUNT",
	normalAccount:              "NORMAL_ACCOUNT",
	interdomainTrustAccount:    "INTERDOMAIN_TRUST_ACCOUNT",
	workstationTrustAccount:    "WORKSTATION_TRUST_ACCOUNT",
	serverTrustAccount:         "SERVER_TRUST_ACCOUNT",
	dontExpirePassword:         "DONT_EXPIRE_PASSWORD",
	mnsLogonAccount:            "MNS_LOGON_ACCOUNT",
	smartcardRequired:          "SMARTCARD_REQUIRED",
	trustedForDelegation:       "TRUSTED_FOR_DELEGATION",
	notDelegated:               "NOT_DELEGATED",
	useDesKeyOnly:              "USE_DES_KEY_ONLY",
	dontReqPreauth:             "DONT_REQ_PREAUTH",
	passwordExpired:            "PASSWORD_EXPIRED",
	trustedToAuthForDelegation: "TRUSTED_TO_AUTH_FOR_DELEGATION",
	partialSecretsAccount:      "PARTIAL_SECRETS_ACCOUNT",
}

// ParseUAC will provide the caller with a collection of option names,
// given the UserAccountControl integer from an LDAP query
func ParseUAC(uacInt int64) (flags []string, err error) {
	values, err := bamflags.ParseInt(uacInt)
	if err != nil {
		return
	}

	for _, value := range values {
		if propName := PropertyMap[value]; propName != "" {
			flags = append(flags, propName)
		}
	}
	return
}
