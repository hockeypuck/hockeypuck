/*
   Hockeypuck - OpenPGP key server
   Copyright (C) 2012-2025  Casey Marshall and the Hockeypuck Contributors

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

package openpgp

import (
	"unicode/utf8"

	"github.com/pkg/errors"
)

// CleanUtf8 ensures that string values are safe.
// It should be called any time a string is extracted from a raw (sub)packet into a parsed field.
// The caller SHOULD abort processing the (sub)packet if an error is thrown.
func CleanUtf8(s string) (string, error) {
	var runes []rune
	for _, r := range s {
		if r == utf8.RuneError {
			r = '?'
		}
		// Nulls in strings break postgres, and are an attack vector against clients.
		// (https://hackaday.com/2009/07/29/black-hat-2009-breaking-ssl-with-null-characters/)
		if r == 0 {
			return "", errors.Errorf("null byte found in string")
		}
		// C0 controls are ignored (TODO: should we error out like nulls?)
		// C1 controls probably should be also, but CP1252 is common in the wild.
		if r < 0x20 || r == 0x7f {
			continue
		}
		runes = append(runes, r)
	}
	return string(runes), nil
}
