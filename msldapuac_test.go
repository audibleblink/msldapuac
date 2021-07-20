package msldapuac

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestParseUAC(t *testing.T) {
	input := int64(514)
	expect := []string{"NORMAL_ACCOUNT", "ACCOUNTDISABLE"}

	got, err := ParseUAC(input)
	assert.Nil(t, err)

	for _, gotEl := range got {
		assert.Contains(t, expect, gotEl)
	}

	input = PartialSecretsAccount | NotDelegated | Script
	expect = []string{"PARTIAL_SECRETS_ACCOUNT", "NOT_DELEGATED", "SCRIPT"}

	got, err = ParseUAC(input)
	assert.Nil(t, err)

	for _, gotEl := range got {
		assert.Contains(t, expect, gotEl)
	}

	num := TrustedForDelegation | NormalAccount
	assert.Equal(t, num, 524800)
}

func TestIsSet(t *testing.T) {
	got := IsSet(int64(514), Accountdisable)
	assert.True(t, got)

	got = IsSet(int64(520), Accountdisable)
	assert.False(t, got)
}
