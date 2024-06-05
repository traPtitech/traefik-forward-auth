package authrule

import (
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"testing"
)

type m = map[string]any

func TestAuthRule(t *testing.T) {
	allowedFields := []string{"id", "email", "nested.name", "non-existent", "nested.non-existent"}
	obj := m{
		"email": "user@example.com",
		"id":    "user",
		"nested": m{
			"name": "user name",
		},
	}

	t.Run("True function", func(t *testing.T) {
		pr, err := NewAuthRule("True()", allowedFields)
		require.NoError(t, err)
		require.True(t, pr(obj))
	})

	t.Run("In function", func(t *testing.T) {
		pr, err := NewAuthRule("In(`id`, `user`)", allowedFields)
		require.NoError(t, err)
		assert.True(t, pr(obj))

		pr, err = NewAuthRule("In(`id`, `admin`)", allowedFields)
		require.NoError(t, err)
		assert.False(t, pr(obj))

		pr, err = NewAuthRule("In(`id`, `admin`, `user`)", allowedFields)
		require.NoError(t, err)
		assert.True(t, pr(obj))
	})

	t.Run("Regexp function", func(t *testing.T) {
		pr, err := NewAuthRule("Regexp(`email`, `^user@example\\.com$`)", allowedFields)
		require.NoError(t, err)
		assert.True(t, pr(obj))

		pr, err = NewAuthRule("Regexp(`email`, `^admin@example\\.com$`)", allowedFields)
		require.NoError(t, err)
		assert.False(t, pr(obj))

		pr, err = NewAuthRule("Regexp(`email`, `^.+@example\\.com$`)", allowedFields)
		require.NoError(t, err)
		assert.True(t, pr(obj))

		pr, err = NewAuthRule("Regexp(`email`, `^.+@company\\.com$`)", allowedFields)
		require.NoError(t, err)
		assert.False(t, pr(obj))

		// Invalid regexp
		pr, err = NewAuthRule("Regexp(`email`, `[incomplete`)", allowedFields)
		assert.Error(t, err)
	})

	t.Run("Nested fields", func(t *testing.T) {
		pr, err := NewAuthRule("In(`nested.name`, `user name`)", allowedFields)
		require.NoError(t, err)
		assert.True(t, pr(obj))

		pr, err = NewAuthRule("In(`nested.name`, `admin name`)", allowedFields)
		require.NoError(t, err)
		assert.False(t, pr(obj))
	})

	t.Run("Non existent paths", func(t *testing.T) {
		pr, err := NewAuthRule("In(`non-existent`, `user`)", allowedFields)
		require.NoError(t, err)
		assert.False(t, pr(obj))

		pr, err = NewAuthRule("In(`nested.non-existent`, `user name`)", allowedFields)
		require.NoError(t, err)
		assert.False(t, pr(obj))

		pr, err = NewAuthRule("Regexp(`non-existent`, `^name$`)", allowedFields)
		require.NoError(t, err)
		assert.False(t, pr(obj))

		pr, err = NewAuthRule("Regexp(`nested.non-existent`, `name`)", allowedFields)
		require.NoError(t, err)
		assert.False(t, pr(obj))
	})

	t.Run("Disallowed fields", func(t *testing.T) {
		_, err := NewAuthRule("In(`disallowed`, `user`)", allowedFields)
		assert.Error(t, err)

		_, err = NewAuthRule("In(`nested.id`, `user`)", allowedFields)
		assert.Error(t, err)

		_, err = NewAuthRule("In(`id`, `user`)", []string{})
		assert.Error(t, err)
	})

	t.Run("And function", func(t *testing.T) {
		pr, err := NewAuthRule("In(`email`, `user@example.com`) && In(`id`, `user`)", allowedFields)
		require.NoError(t, err)
		assert.True(t, pr(obj))

		pr, err = NewAuthRule("In(`email`, `user@example.com`) && In(`id`, `admin`)", allowedFields)
		require.NoError(t, err)
		assert.False(t, pr(obj))

		pr, err = NewAuthRule("In(`email`, `admin@example.com`) && In(`id`, `user`)", allowedFields)
		require.NoError(t, err)
		assert.False(t, pr(obj))

		pr, err = NewAuthRule("In(`email`, `admin@example.com`) && In(`id`, `admin`)", allowedFields)
		require.NoError(t, err)
		assert.False(t, pr(obj))

		// Invalid regexp
		pr, err = NewAuthRule("In(`email`, `user@example.com`) && Regexp(`email`, `[incomplete`)", allowedFields)
		assert.Error(t, err)
	})

	t.Run("Or function", func(t *testing.T) {
		pr, err := NewAuthRule("In(`email`, `user@example.com`) || In(`id`, `user`)", allowedFields)
		require.NoError(t, err)
		assert.True(t, pr(obj))

		pr, err = NewAuthRule("In(`email`, `user@example.com`) || In(`id`, `admin`)", allowedFields)
		require.NoError(t, err)
		assert.True(t, pr(obj))

		pr, err = NewAuthRule("In(`email`, `admin@example.com`) || In(`id`, `user`)", allowedFields)
		require.NoError(t, err)
		assert.True(t, pr(obj))

		pr, err = NewAuthRule("In(`email`, `admin@example.com`) || In(`id`, `admin`)", allowedFields)
		require.NoError(t, err)
		assert.False(t, pr(obj))

		// Invalid regexp
		pr, err = NewAuthRule("In(`email`, `user@example.com`) || Regexp(`email`, `[incomplete`)", allowedFields)
		assert.Error(t, err)
	})

	t.Run("Not function", func(t *testing.T) {
		pr, err := NewAuthRule("!In(`email`, `user@example.com`)", allowedFields)
		require.NoError(t, err)
		assert.False(t, pr(obj))

		pr, err = NewAuthRule("!In(`email`, `admin@example.com`)", allowedFields)
		require.NoError(t, err)
		assert.True(t, pr(obj))

		pr, err = NewAuthRule("!Regexp(`email`, `^.+@example\\.com$`)", allowedFields)
		require.NoError(t, err)
		assert.False(t, pr(obj))

		pr, err = NewAuthRule("!Regexp(`email`, `^.+@company\\.com$`)", allowedFields)
		require.NoError(t, err)
		assert.True(t, pr(obj))

		// Invalid regexp
		pr, err = NewAuthRule("!Regexp(`email`, `[incomplete`)", allowedFields)
		assert.Error(t, err)
	})
}
