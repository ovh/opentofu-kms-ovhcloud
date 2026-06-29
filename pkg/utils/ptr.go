// SPDX-FileCopyrightText: 2026 OVH SAS <opensource@ovh.net>
//
// SPDX-License-Identifier: Apache-2.0

package utils

// PtrTo returns a pointer to the given value.
func PtrTo[T any](v T) *T {
	return &v
}
