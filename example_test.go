package passvalidator

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestExample(t *testing.T) {
	err := Example("#Password@8249!")

	assert.NoError(t, err)
}
