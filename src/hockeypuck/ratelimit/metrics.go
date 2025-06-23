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

package ratelimit

import (
	"hockeypuck/ratelimit/types"
)

// Type aliases for metrics types
type IPMetrics = types.IPMetrics
type BanRecord = types.BanRecord
type BackendStats = types.BackendStats
type TorStats = types.TorStats
type ConnectionTracker = types.ConnectionTracker
type RequestTracker = types.RequestTracker
