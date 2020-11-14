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

// Package dirs specifies the location of snapd-relevant directories
// and offers helpers to work with them including when they
// are mounted not at their canonical location.
package dirs

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/snapcore/snapd/release"
)

// Dir represents a directory at a well-known location.
type Dir struct {
	// Path is the directory path.
	Path string
	// props is a bit field with internal properties (system properties, non-canonical root-length).
	props int
}

func (d Dir) prop(mask int) int {
	return d.props & mask
}

func (d Dir) propIsSet(mask int) bool {
	return d.prop(mask) != 0
}

// Ensure creates this directory, along with any necessary parents.
// Mode is used for any directory to create. If the directory already
// exists it does nothing.
func (d Dir) Ensure(mode os.FileMode) error {
	return os.MkdirAll(d.Path, mode)
}

// Join joins this directory path with the given path elements.
func (d Dir) Join(elem ...string) string {
	return filepath.Join(d.Path, filepath.Join(elem...))
}

// Subdir creates a new Dir representing the subdirectory of this directory
// specified by the chain of path elements. It is responsibility of the caller
// not to pass ".." in elements that would result in a parent directory.
func (d Dir) Subdir(elem ...string) Dir {
	return Dir{Path: d.Join(elem...), props: d.props}
}

// RootRel joins this directory path with the given path elements and
// returns a canonical presentation as relative to the potentially
// non-canonical root under which this directory might have been
// constructed.
func (d Dir) RootRel(elem ...string) string {
	p := d.Join(elem...)
	rootLen := d.prop(propRootLen)
	rel := p[rootLen:]
	if rel == "" {
		return "/"
	}
	return rel
}

const (
	// process is inside base snap filesystem
	propInsideBaseSnap = 0x10000 << iota
	// distro uses alternative directory to mount snaps
	propAltSnapMountDistro
	// distro uses /usr/libexec
	propLibExecDistro

	// propRootLen is the bit mask for the non-canonical root length property of Dir
	propRootLen = 0xffff
)

var altDirDistros = []string{
	"antergos",
	"arch",
	"archlinux",
	"fedora",
	"gentoo",
	"manjaro",
	"manjaro-arm",
}

// A RootTree represents the tree of snapd-relevant directories and file paths
// in the root filesystem of a running system.
type RootTree struct {
	Dir
}

// DefaultRootTreeAt creates a RootTree located at the given
// potentially non-canonical rootdir.
// The created tree is a default one and ignores the characteristics
// of the running distro and process.
func DefaultRootTreeAt(rootdir string) RootTree {
	if rootdir == "" {
		rootdir = "/"
	}
	return RootTree{Dir{Path: rootdir, props: rootLen(rootdir)}}
}

// RootTreeAt creates a RootTree located at the given potentially non-canonical
// rootdir.
// The created tree will reflect the detected characteristics of the running
// distro and process.
func RootTreeAt(rootdir string) RootTree {
	r := DefaultRootTreeAt(rootdir)
	r.props |= detectRootTreeProps()
	return r
}

func rootLen(rootdir string) int {
	if rootdir == "/" {
		return 0
	}
	return len(rootdir)
}

func detectRootTreeProps() int {
	props := 0
	insideBase, _ := isInsideBaseSnap()
	if insideBase {
		props |= propInsideBaseSnap
	}
	if release.DistroLike(altDirDistros...) {
		props |= propAltSnapMountDistro
	}
	return props
}

// Rel produces a presentation of the given path relative to this root tree.
// It proceeds stripping from p the potentially non-canonical root of
// the tree. If p is the root itself it returns "/".  It panics if p
// is not an absolute path or p doesn't belong to the tree.
func (r RootTree) Rel(p string) string {
	if !filepath.IsAbs(p) {
		panic(fmt.Sprintf("supplied path is not absolute %q", p))
	}
	if !strings.HasPrefix(p, r.Path) {
		panic(fmt.Sprintf("supplied path %q is not related to root tree %q", p, r.Path))
	}
	result, err := filepath.Rel(r.Path, p)
	if err != nil {
		panic(err)
	}
	if result == "." {
		return "/"
	}
	return "/" + result
}

// SnapMount returns the directory tree under which snaps are mounted.
func (r RootTree) SnapMount() Dir {
	if !r.propIsSet(propInsideBaseSnap) && r.propIsSet(propAltSnapMountDistro) {
		return r.Subdir("/var/lib/snapd/snap")
	}
	return r.Subdir(defaultSnapMountDir)
}

// SnapServices returns the directory under which service units are maintained.
func (r RootTree) SnapServices() Dir {
	return r.Subdir("/etc/systemd/system")
}

// XXX ...

// Root is the global RootTree of snapd-relevant directories.
// It can be relocated for tests with SetRootDir.
var Root RootTree

// XXX SnapMount (?)

// XXX SnapdTree
// XXX DeviceTree
// XXX SaveTree
