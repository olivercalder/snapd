// -*- Mode: Go; indent-tabs-mode: t -*-

/*
 * Copyright (C) 2020 Canonical Ltd
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 3 as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

package boot

import (
	"bytes"
	"encoding/json"
	"sort"
)

type bootChain struct {
	Model          string      `json:"model"`
	BrandID        string      `json:"brand-id"`
	Grade          string      `json:"grade"`
	ModelSignKeyID string      `json:"model-sign-key-id"`
	AssetChain     []bootAsset `json:"asset-chain"`
	Kernel         string      `json:"kernel"`
	// KernelRevision is the revision of the kernel snap. It is empty if
	// kernel is unasserted, in which case always reseal.
	KernelRevision string `json:"kernel-revision"`
	KernelCmdline  string `json:"kernel-cmdline"`
}

type bootAsset struct {
	Role   string   `json:"role"`
	Name   string   `json:"name"`
	Hashes []string `json:"hashes"`
}

func bootAssetLess(b, other *bootAsset) bool {
	byRole := b.Role < other.Role
	byName := b.Name < other.Name
	// sort order: role -> name -> hash list (len -> lexical)
	if b.Role != other.Role {
		return byRole
	}
	if b.Name != other.Name {
		return byName
	}
	return hashListsLess(b.Hashes, other.Hashes)
}

func hashListsLess(h1, h2 []string) bool {
	if len(h1) != len(h2) {
		return len(h1) < len(h2)
	}
	for idx := range h1 {
		if h1[idx] < h2[idx] {
			return true
		}
	}
	return false
}

func toPredictableBootAsset(b *bootAsset) *bootAsset {
	if b == nil {
		return nil
	}
	newB := *b
	if b.Hashes != nil {
		newB.Hashes = make([]string, len(b.Hashes))
		copy(newB.Hashes, b.Hashes)
		sort.Strings(newB.Hashes)
	}
	return &newB
}

type byBootAssetOrder []bootAsset

func (b byBootAssetOrder) Len() int      { return len(b) }
func (b byBootAssetOrder) Swap(i, j int) { b[i], b[j] = b[j], b[i] }
func (b byBootAssetOrder) Less(i, j int) bool {
	return bootAssetLess(&b[i], &b[j])
}

func toPredictableBootChain(b *bootChain) *bootChain {
	if b == nil {
		return nil
	}
	newB := *b
	if b.AssetChain != nil {
		newB.AssetChain = make([]bootAsset, len(b.AssetChain))
		for i := range b.AssetChain {
			newB.AssetChain[i] = *toPredictableBootAsset(&b.AssetChain[i])
		}
		sort.Sort(byBootAssetOrder(newB.AssetChain))
	}
	return &newB
}

// equal returns true when boot chains are equivalent for reseal.
func (b *bootChain) equalForReseal(other *bootChain) bool {
	bJSON, err := json.Marshal(toPredictableBootChain(b))
	if err != nil {
		return false
	}
	otherJSON, err := json.Marshal(toPredictableBootChain(other))
	if err != nil {
		return false
	}
	return bytes.Equal(bJSON, otherJSON)
}

func predictableBootAssetsLess(b1, b2 []bootAsset) bool {
	if len(b1) != len(b2) {
		return len(b1) < len(b2)
	}
	for i := range b1 {
		if bootAssetLess(&b1[i], &b2[i]) {
			return true
		}
	}
	return false
}

type byBootChainOrder []bootChain

func (b byBootChainOrder) Len() int      { return len(b) }
func (b byBootChainOrder) Swap(i, j int) { b[i], b[j] = b[j], b[i] }
func (b byBootChainOrder) Less(i, j int) bool {
	if b[i].Model != b[j].Model {
		return b[i].Model < b[j].Model
	}
	if b[i].BrandID != b[j].BrandID {
		return b[i].BrandID < b[j].BrandID
	}
	if b[i].Grade != b[j].Grade {
		return b[i].Grade < b[j].Grade
	}
	if b[i].ModelSignKeyID != b[j].ModelSignKeyID {
		return b[i].ModelSignKeyID < b[j].ModelSignKeyID
	}
	if b[i].Kernel != b[j].Kernel {
		return b[i].Kernel < b[j].Kernel
	}
	if b[i].KernelRevision != b[j].KernelRevision {
		return b[i].KernelRevision < b[j].KernelRevision
	}
	if b[i].KernelCmdline != b[j].KernelCmdline {
		return b[i].KernelCmdline < b[j].KernelCmdline
	}
	// XXX: add new fields as when bootChain is modified
	return predictableBootAssetsLess(b[i].AssetChain, b[j].AssetChain)
}

func toPredictableBootChains(chains []bootChain) []bootChain {
	if chains == nil {
		return nil
	}
	predictableChains := make([]bootChain, len(chains))
	for i := range chains {
		predictableChains[i] = *toPredictableBootChain(&chains[i])
	}
	sort.Sort(byBootChainOrder(predictableChains))
	return predictableChains
}
