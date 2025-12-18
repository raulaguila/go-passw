package passw

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestValidator(t *testing.T) {
	assert.NoError(t, Validator("#Password@8249!"))
}
