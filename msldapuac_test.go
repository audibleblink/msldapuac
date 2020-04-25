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
}
