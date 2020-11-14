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

package dirs_test

import (
	"io/ioutil"
	"os"
	"path/filepath"
	"reflect"

	. "gopkg.in/check.v1"

	"github.com/snapcore/snapd/dirs"
	"github.com/snapcore/snapd/release"
)

type dirSuite struct{}

var _ = Suite(&dirSuite{})

func (s *dirSuite) TestEnsure(c *C) {
	top := c.MkDir()

	dir := dirs.Dir{Path: filepath.Join(top, "adir")}
	c.Check(dir.Path, Equals, filepath.Join(top, "adir"))

	err := dir.Ensure(0700)
	c.Assert(err, IsNil)

	st, err := os.Stat(dir.Path)
	c.Assert(err, IsNil)
	c.Check(st.IsDir(), Equals, true)
	c.Check(st.Mode().Perm(), Equals, os.FileMode(0700))
}

func (s *dirSuite) TestJoin(c *C) {
	top := c.MkDir()

	dir := dirs.Dir{Path: filepath.Join(top, "adir")}

	c.Check(dir.Join(), Equals, dir.Path)
	c.Check(dir.Join("a"), Equals, filepath.Join(dir.Path, "a"))
	c.Check(dir.Join("a", "//b/"), Equals, filepath.Join(dir.Path, "a/b"))
}

func (s *dirSuite) TestSubdir(c *C) {
	top := c.MkDir()

	dir := dirs.Dir{Path: filepath.Join(top, "adir")}

	c.Check(dir.Subdir().Path, Equals, dir.Path)
	c.Check(dir.Subdir("a").Path, Equals, filepath.Join(dir.Path, "a"))
	c.Check(dir.Subdir("a", "//b/").Path, Equals, filepath.Join(dir.Path, "a/b"))
}

func (s *dirSuite) TestRootRel(c *C) {
	croot := dirs.Dir{Path: "/"}
	c.Check(croot.RootRel(), Equals, "/")

	dir := dirs.Dir{Path: "/a"}
	c.Check(dir.RootRel(), Equals, "/a")
	c.Check(dir.RootRel("b"), Equals, "/a/b")

	subdir := dir.Subdir("/b", "//c/")
	c.Check(subdir.RootRel(), Equals, "/a/b/c")
	c.Check(subdir.RootRel("d", "e"), Equals, "/a/b/c/d/e")

	// XXX test panics
}

type rootTreeSuite struct{}

var _ = Suite(&rootTreeSuite{})

func (s *rootTreeSuite) TestBasics(c *C) {
	top := c.MkDir()
	r := dirs.RootTreeAt(top)
	c.Assert(r.Path, Equals, top)

	c.Check(r.Join("foo"), Equals, filepath.Join(top, "foo"))
}

func (s *rootTreeSuite) TestRootRel(c *C) {
	top := c.MkDir()
	r := dirs.RootTreeAt(top)

	c.Assert(r.RootRel(), Equals, "/")

	dir := r.Subdir("a")
	c.Check(dir.RootRel(), Equals, "/a")
	c.Check(dir.RootRel("b"), Equals, "/a/b")

	subdir := dir.Subdir("/b", "//c/")
	c.Check(subdir.RootRel(), Equals, "/a/b/c")
	c.Check(subdir.RootRel("d", "e"), Equals, "/a/b/c/d/e")
}

func (s *rootTreeSuite) TestRel(c *C) {
	top := c.MkDir()
	r := dirs.RootTreeAt(top)

	c.Assert(r.Rel(top), Equals, "/")

	c.Check(r.Rel(filepath.Join(top, "a")), Equals, "/a")
	c.Check(r.Rel(filepath.Join(top, "a/b/c")), Equals, "/a/b/c")
}

func (s *rootTreeSuite) TestCanonicalRoot(c *C) {
	r := dirs.RootTreeAt("")
	c.Check(r.Path, Equals, "/")

	c.Assert(r.RootRel(), Equals, "/")

	dir := r.Subdir("a")
	c.Check(dir.RootRel(), Equals, "/a")
	c.Check(dir.RootRel("b"), Equals, "/a/b")

	subdir := dir.Subdir("/b", "//c/")
	c.Check(subdir.RootRel(), Equals, "/a/b/c")
	c.Check(subdir.RootRel("d", "e"), Equals, "/a/b/c/d/e")

	c.Assert(r.Rel("/"), Equals, "/")

	c.Check(r.Rel("/a"), Equals, "/a")
	c.Check(r.Rel("/a/b/c"), Equals, "/a/b/c")
}

func (s *rootTreeSuite) TestSnapMount(c *C) {
	top := c.MkDir()

	landmarkSnapYaml := filepath.Join(top, "meta/snap.yaml")
	restore := dirs.MockMetaSnapPath(landmarkSnapYaml)
	defer restore()
	c.Assert(os.MkdirAll(filepath.Dir(landmarkSnapYaml), 0755), IsNil)

	tests := []struct {
		distro     string
		insideBase bool
		alt        bool
	}{
		{distro: "ubuntu", insideBase: false, alt: false},
		{distro: "ubuntu", insideBase: true, alt: false},
		{distro: "debian", insideBase: false, alt: false},
		{distro: "debian", insideBase: true, alt: false},
		{distro: "fedora", insideBase: false, alt: true},
		{distro: "fedora", insideBase: true, alt: false},
		{distro: "antergos", insideBase: false, alt: true},
		{distro: "arch", insideBase: false, alt: true},
		{distro: "archlinux", insideBase: false, alt: true},
		{distro: "gentoo", insideBase: false, alt: true},
		{distro: "manjaro", insideBase: false, alt: true},
		{distro: "manjaro-arm", insideBase: false, alt: true},
	}

	for _, t := range tests {
		defer release.MockReleaseInfo(&release.OS{ID: t.distro})()

		os.Remove(landmarkSnapYaml)
		if t.insideBase {
			err := ioutil.WriteFile(landmarkSnapYaml, nil, 0755)
			c.Assert(err, IsNil)
		}

		r := dirs.RootTreeAt(top)
		snapMount := r.SnapMount()
		if !t.alt {
			c.Check(snapMount.RootRel(), Equals, "/snap")
		} else {
			c.Check(snapMount.RootRel(), Equals, "/var/lib/snapd/snap", Commentf("%#v", t))
		}

		dr := dirs.DefaultRootTreeAt(top)
		c.Check(dr.SnapMount().RootRel(), Equals, "/snap")
	}
}

func callDirMethod(c *C, tree reflect.Value, name string) dirs.Dir {
	comm := Commentf("testing %s", name)
	m := tree.MethodByName(name)
	c.Assert(m == reflect.Value{}, Equals, false, comm)
	res := m.Call(nil)
	c.Assert(res, HasLen, 1, comm)
	return res[0].Interface().(dirs.Dir)
}

func (s *rootTreeSuite) TestSimpleSubdirDefs(c *C) {
	top := c.MkDir()

	tests := map[string]string{
		"SnapServices": "/etc/systemd/system",
	}

	r := dirs.RootTreeAt("")
	rv := reflect.ValueOf(r)
	rnoncanon := dirs.RootTreeAt(top)
	rnoncanonv := reflect.ValueOf(rnoncanon)

	for name, p := range tests {
		c.Check(callDirMethod(c, rv, name).Path, Equals, p)
		c.Check(callDirMethod(c, rnoncanonv, name).RootRel(), Equals, p)
	}
}

func (s *rootTreeSuite) TestRoot(c *C) {
	c.Check(dirs.Root.Path, Equals, "/")
	c.Check(dirs.Root.SnapServices().Path, Equals, "/etc/systemd/system")
}
