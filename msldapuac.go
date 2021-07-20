package msldapuac

import (
	"github.com/audibleblink/bamflags"
)

const (
	Script                     = 1 << iota // 1
	Accountdisable                         // 2
	_                                      // noop
	HomedirRequired                        // 8
	Lockout                                // 16
	PasswdNotReqd                          // 32
	PasswdCantChange                       // 64
	EncryptedTextPwdAllowed                // 128
	TempDuplicateAccount                   // 256
	NormalAccount                          // 512
	_                                      // noop
	InterdomainTrustAccount                // 2048
	WorkstationTrustAccount                // 4096
	ServerTrustAccount                     // 8192
	_                                      // noop
	_                                      // noop
	DontExpirePassword                     // 65536
	MnsLogonAccount                        // 131072
	SmartcardRequired                      // 262144
	TrustedForDelegation                   // 524288
	NotDelegated                           // 1048576
	UseDesKeyOnly                          // 2097152
	DontReqPreauth                         // 4194304
	PasswordExpired                        // 8388608
	TrustedToAuthForDelegation             // 16777216
	_                                      // noop
	PartialSecretsAccount                  // 67108864
)

// PropertyMap holds the Microsoft-defined values for all possible flags
// in the UserAccountControl LDAP field
//
// https://support.microsoft.com/en-us/help/305144
var PropertyMap = map[int]string{
	Script:                     "SCRIPT",
	Accountdisable:             "ACCOUNTDISABLE",
	HomedirRequired:            "HOMEDIR_REQUIRED",
	Lockout:                    "LOCKOUT",
	PasswdNotReqd:              "PASSWD_NOTREQD",
	PasswdCantChange:           "PASSWD_CANT_CHANGE",
	EncryptedTextPwdAllowed:    "ENCRYPTED_TEXT_PWD_ALLOWED",
	TempDuplicateAccount:       "TEMP_DUPLICATE_ACCOUNT",
	NormalAccount:              "NORMAL_ACCOUNT",
	InterdomainTrustAccount:    "INTERDOMAIN_TRUST_ACCOUNT",
	WorkstationTrustAccount:    "WORKSTATION_TRUST_ACCOUNT",
	ServerTrustAccount:         "SERVER_TRUST_ACCOUNT",
	DontExpirePassword:         "DONT_EXPIRE_PASSWORD",
	MnsLogonAccount:            "MNS_LOGON_ACCOUNT",
	SmartcardRequired:          "SMARTCARD_REQUIRED",
	TrustedForDelegation:       "TRUSTED_FOR_DELEGATION",
	NotDelegated:               "NOT_DELEGATED",
	UseDesKeyOnly:              "USE_DES_KEY_ONLY",
	DontReqPreauth:             "DONT_REQ_PREAUTH",
	PasswordExpired:            "PASSWORD_EXPIRED",
	TrustedToAuthForDelegation: "TRUSTED_TO_AUTH_FOR_DELEGATION",
	PartialSecretsAccount:      "PARTIAL_SECRETS_ACCOUNT",
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

// IsSet will inform the caller whether or not a particular flag
// is set in a user's UserAccountControl BAM property
// Example: IsSet(514, msldapuac.Accountdisable) == true
func IsSet(bam int64, flagValue int) bool {
	return bamflags.Contains(bam, int64(flagValue))
}
