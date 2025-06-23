/*
   Hockeypuck - OpenPGP key server
   Copyright (C) 2012-2025 Hockeypuck Contributors

   This program is free software: you can redistribute it and/or modify
   it under the terms of the GNU Affero General Public License as published by
   the Free Software Foundation, version 3.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU Affero General Public License for more details.

   You should have received a copy of the GNU Affero General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

package backend

import (
	"errors"
	"testing"
)

// Mock backend for testing
type mockBackend struct {
	name string
}

func mockConstructor(config interface{}) (interface{}, error) {
	if config == nil {
		return nil, errors.New("config is required")
	}

	if configMap, ok := config.(map[string]interface{}); ok {
		if name, exists := configMap["name"]; exists {
			return &mockBackend{name: name.(string)}, nil
		}
	}

	return &mockBackend{name: "default"}, nil
}

func failingConstructor(config interface{}) (interface{}, error) {
	return nil, errors.New("construction failed")
}

func TestRegister(t *testing.T) {
	// Clear existing constructors
	constructors = make(map[string]Constructor)

	// Test registering a constructor
	Register("mock", mockConstructor)

	if len(constructors) != 1 {
		t.Errorf("Expected 1 constructor registered, got %d", len(constructors))
	}

	if _, exists := constructors["mock"]; !exists {
		t.Error("Mock constructor should be registered")
	}
}

func TestRegisterMultiple(t *testing.T) {
	// Clear existing constructors
	constructors = make(map[string]Constructor)

	// Register multiple constructors
	Register("mock1", mockConstructor)
	Register("mock2", mockConstructor)
	Register("failing", failingConstructor)

	if len(constructors) != 3 {
		t.Errorf("Expected 3 constructors registered, got %d", len(constructors))
	}

	for _, name := range []string{"mock1", "mock2", "failing"} {
		if _, exists := constructors[name]; !exists {
			t.Errorf("Constructor %s should be registered", name)
		}
	}
}

func TestNewSuccess(t *testing.T) {
	// Clear existing constructors
	constructors = make(map[string]Constructor)

	// Register mock constructor
	Register("mock", mockConstructor)

	// Test successful creation
	config := map[string]interface{}{
		"name": "test-backend",
	}

	backend, err := New("mock", config)
	if err != nil {
		t.Errorf("New should not error: %v", err)
	}

	if backend == nil {
		t.Error("Backend should not be nil")
	}

	if mockBackend, ok := backend.(*mockBackend); ok {
		if mockBackend.name != "test-backend" {
			t.Errorf("Expected backend name 'test-backend', got '%s'", mockBackend.name)
		}
	} else {
		t.Error("Backend should be of type *mockBackend")
	}
}

func TestNewUnknownBackend(t *testing.T) {
	// Clear existing constructors
	constructors = make(map[string]Constructor)

	// Test unknown backend type
	_, err := New("unknown", nil)
	if err == nil {
		t.Error("Expected error for unknown backend type")
	}

	if err.Error() != "unknown backend type: unknown" {
		t.Errorf("Unexpected error message: %v", err)
	}
}

func TestNewConstructorError(t *testing.T) {
	// Clear existing constructors
	constructors = make(map[string]Constructor)

	// Register failing constructor
	Register("failing", failingConstructor)

	// Test constructor that returns error
	_, err := New("failing", nil)
	if err == nil {
		t.Error("Expected error from failing constructor")
	}

	if err.Error() != "construction failed" {
		t.Errorf("Unexpected error message: %v", err)
	}
}

func TestNewWithNilConfig(t *testing.T) {
	// Clear existing constructors
	constructors = make(map[string]Constructor)

	// Register mock constructor
	Register("mock", mockConstructor)

	// Test with nil config
	_, err := New("mock", nil)
	if err == nil {
		t.Error("Expected error with nil config")
	}

	if err.Error() != "config is required" {
		t.Errorf("Unexpected error message: %v", err)
	}
}

func TestNewWithDefaultConfig(t *testing.T) {
	// Clear existing constructors
	constructors = make(map[string]Constructor)

	// Register mock constructor
	Register("mock", mockConstructor)

	// Test with empty config (should use default)
	config := map[string]interface{}{}

	backend, err := New("mock", config)
	if err != nil {
		t.Errorf("New should not error: %v", err)
	}

	if mockBackend, ok := backend.(*mockBackend); ok {
		if mockBackend.name != "default" {
			t.Errorf("Expected backend name 'default', got '%s'", mockBackend.name)
		}
	} else {
		t.Error("Backend should be of type *mockBackend")
	}
}

func TestConstructorsIsolation(t *testing.T) {
	// Save original constructors
	originalConstructors := constructors
	defer func() {
		constructors = originalConstructors
	}()

	// Clear and test isolation
	constructors = make(map[string]Constructor)

	Register("test1", mockConstructor)
	if len(constructors) != 1 {
		t.Error("Constructors should be isolated")
	}

	// Reset to empty again
	constructors = make(map[string]Constructor)
	if len(constructors) != 0 {
		t.Error("Constructors should be cleared")
	}
}

func TestRegisterOverwrite(t *testing.T) {
	// Clear existing constructors
	constructors = make(map[string]Constructor)

	// Register a constructor
	Register("test", mockConstructor)

	// Register another constructor with the same name (overwrite)
	Register("test", failingConstructor)

	if len(constructors) != 1 {
		t.Errorf("Expected 1 constructor after overwrite, got %d", len(constructors))
	}

	// Test that the second constructor is used
	_, err := New("test", map[string]interface{}{})
	if err == nil {
		t.Error("Expected error from overwritten constructor")
	}

	if err.Error() != "construction failed" {
		t.Errorf("Expected 'construction failed', got '%s'", err.Error())
	}
}
