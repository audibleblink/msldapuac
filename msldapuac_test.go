package msldapuac

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestParseUAC(t *testing.T) {
	input := int64(514)
	expect := []string{"NORMAL_ACCOUNT", "ACCOUNTDISABLE"}
	got, err := ParseUAC(input)

	assert.Equal(t, expect, got)
	assert.Nil(t, err)

	input = PartialSecretsAccount | NotDelegated | Script
	expect = []string{"PARTIAL_SECRETS_ACCOUNT", "NOT_DELEGATED", "SCRIPT"}
	got, err = ParseUAC(input)

	assert.Equal(t, expect, got)
	assert.Nil(t, err)

	num := TrustedForDelegation | NormalAccount
	assert.Equal(t, num, 524800)
}
