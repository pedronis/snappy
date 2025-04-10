// -*- Mode: Go; indent-tabs-mode: t -*-

/*
 * Copyright (C) 2017-2020 Canonical Ltd
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

package snapdtool_test

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	. "gopkg.in/check.v1"

	"github.com/snapcore/snapd/dirs"
	"github.com/snapcore/snapd/dirs/dirstest"
	"github.com/snapcore/snapd/logger"
	"github.com/snapcore/snapd/release"
	"github.com/snapcore/snapd/snapdtool"
	"github.com/snapcore/snapd/testutil"
)

func Test(t *testing.T) { TestingT(t) }

type toolSuite struct {
	testutil.BaseTest

	execCalled    int
	lastExecArgv0 string
	lastExecArgv  []string
	lastExecEnvv  []string
	fakeroot      string
	snapdPath     string
	corePath      string
}

var _ = Suite(&toolSuite{})

func (s *toolSuite) SetUpTest(c *C) {
	s.BaseTest.SetUpTest(c)

	s.AddCleanup(snapdtool.MockSyscallExec(s.syscallExec))
	_, restore := logger.MockLogger()
	s.AddCleanup(restore)

	s.AddCleanup(release.MockReleaseInfo(&release.OS{ID: "ubuntu"}))

	s.execCalled = 0
	s.lastExecArgv0 = ""
	s.lastExecArgv = nil
	s.lastExecEnvv = nil
	s.fakeroot = c.MkDir()
	dirs.SetRootDir(s.fakeroot)
	s.AddCleanup(func() { dirs.SetRootDir("/") })

	s.snapdPath = filepath.Join(dirs.SnapMountDir, "/snapd/42")
	s.corePath = filepath.Join(dirs.SnapMountDir, "/core/21")
	c.Assert(os.MkdirAll(filepath.Join(s.fakeroot, "proc/self"), 0755), IsNil)
}

func (s *toolSuite) syscallExec(argv0 string, argv []string, envv []string) (err error) {
	s.execCalled++
	s.lastExecArgv0 = argv0
	s.lastExecArgv = argv
	s.lastExecEnvv = envv
	return fmt.Errorf(">exec of %q in tests<", argv0)
}

func (s *toolSuite) fakeCoreVersion(c *C, coreDir, version string) {
	p := filepath.Join(coreDir, "/usr/lib/snapd")
	c.Assert(os.MkdirAll(p, 0755), IsNil)
	c.Assert(os.WriteFile(filepath.Join(p, "info"), []byte("VERSION="+version), 0644), IsNil)
}

func makeFakeExe(c *C, path string) {
	err := os.MkdirAll(filepath.Dir(path), 0755)
	c.Assert(err, IsNil)
	err = os.WriteFile(path, nil, 0755)
	c.Assert(err, IsNil)
}

func (s *toolSuite) fakeInternalTool(c *C, coreDir, toolName string) string {
	s.fakeCoreVersion(c, coreDir, "42")
	p := filepath.Join(coreDir, "/usr/lib/snapd", toolName)
	makeFakeExe(c, p)

	return p
}

func (s *toolSuite) mockReExecingEnv() func() {
	restore := []func(){
		release.MockOnClassic(true),
		snapdtool.MockCoreSnapdPaths(s.corePath, s.snapdPath),
		snapdtool.MockVersion("2"),
	}

	return func() {
		for i := len(restore) - 1; i >= 0; i-- {
			restore[i]()
		}
	}
}

func (s *toolSuite) mockReExecFor(c *C, coreDir, toolName, libexecDir string) func() {
	selfExe := filepath.Join(s.fakeroot, "proc/self/exe")
	restore := []func(){
		s.mockReExecingEnv(),
		snapdtool.MockSelfExe(selfExe),
	}
	s.fakeInternalTool(c, coreDir, toolName)
	c.Assert(os.Symlink(filepath.Join(s.fakeroot, libexecDir, toolName), selfExe), IsNil)

	return func() {
		for i := len(restore) - 1; i >= 0; i-- {
			restore[i]()
		}
	}
}

func (s *toolSuite) TestDistroSupportsReExec(c *C) {
	restore := release.MockOnClassic(true)
	defer restore()

	// Some distributions don't support re-execution yet.
	for _, id := range []string{"fedora", "centos", "rhel", "opensuse", "suse", "poky"} {
		restore = release.MockReleaseInfo(&release.OS{ID: id})
		defer restore()
		c.Check(snapdtool.DistroSupportsReExec(), Equals, false, Commentf("ID: %q", id))
	}

	// While others do.
	for _, id := range []string{"debian", "ubuntu"} {
		restore = release.MockReleaseInfo(&release.OS{ID: id})
		defer restore()
		c.Check(snapdtool.DistroSupportsReExec(), Equals, true, Commentf("ID: %q", id))
	}
}

func (s *toolSuite) TestNonClassicDistroNoSupportsReExec(c *C) {
	restore := release.MockOnClassic(false)
	defer restore()

	// no distro supports re-exec when not on classic :-)
	for _, id := range []string{
		"fedora", "centos", "rhel", "opensuse", "suse", "poky",
		"debian", "ubuntu", "arch", "archlinux",
	} {
		restore = release.MockReleaseInfo(&release.OS{ID: id})
		defer restore()
		c.Check(snapdtool.DistroSupportsReExec(), Equals, false, Commentf("ID: %q", id))
	}
}

func (s *toolSuite) TestSystemSnapSupportsReExecNoInfo(c *C) {
	// there's no snapd/info in a just-created tmpdir :-p
	c.Check(snapdtool.SystemSnapSupportsReExec(c.MkDir()), Equals, false)
}

func (s *toolSuite) TestSystemSnapSupportsReExecBadInfo(c *C) {
	// can't read snapd/info if it's a directory
	p := s.snapdPath + "/usr/lib/snapd/info"
	c.Assert(os.MkdirAll(p, 0755), IsNil)

	c.Check(snapdtool.SystemSnapSupportsReExec(s.snapdPath), Equals, false)
}

func (s *toolSuite) TestSystemSnapSupportsReExecBadInfoContent(c *C) {
	// can't understand snapd/info if all it holds are potatoes
	p := s.snapdPath + "/usr/lib/snapd"
	c.Assert(os.MkdirAll(p, 0755), IsNil)
	c.Assert(os.WriteFile(p+"/info", []byte("potatoes"), 0644), IsNil)

	c.Check(snapdtool.SystemSnapSupportsReExec(s.snapdPath), Equals, false)
}

func (s *toolSuite) TestSystemSnapSupportsReExecBadVersion(c *C) {
	// can't understand snapd/info if all its version is gibberish
	s.fakeCoreVersion(c, s.snapdPath, "0:")

	c.Check(snapdtool.SystemSnapSupportsReExec(s.snapdPath), Equals, false)
}

func (s *toolSuite) TestSystemSnapSupportsReExecOldVersion(c *C) {
	// can't re-exec if core version is too old
	defer snapdtool.MockVersion("2")()
	s.fakeCoreVersion(c, s.snapdPath, "0")

	c.Check(snapdtool.SystemSnapSupportsReExec(s.snapdPath), Equals, false)
}

func (s *toolSuite) TestSystemSnapSupportsReExec(c *C) {
	defer snapdtool.MockVersion("2")()
	s.fakeCoreVersion(c, s.snapdPath, "9999")

	c.Check(snapdtool.SystemSnapSupportsReExec(s.snapdPath), Equals, true)
}

func (s *toolSuite) TestInternalToolPathNoReexec(c *C) {
	restore := snapdtool.MockOsReadlink(func(string) (string, error) {
		return filepath.Join(dirs.DistroLibExecDir, "snapd"), nil
	})
	defer restore()

	path, err := snapdtool.InternalToolPath("potato")
	c.Check(err, IsNil)
	c.Check(path, Equals, filepath.Join(dirs.DistroLibExecDir, "potato"))
}

func (s *toolSuite) TestInternalToolPathWithReexec(c *C) {
	s.fakeInternalTool(c, s.snapdPath, "potato")
	restore := snapdtool.MockOsReadlink(func(string) (string, error) {
		return filepath.Join(s.snapdPath, "/usr/lib/snapd/snapd"), nil
	})
	defer restore()

	path, err := snapdtool.InternalToolPath("potato")
	c.Check(err, IsNil)
	c.Check(path, Equals, filepath.Join(dirs.SnapMountDir, "snapd/42/usr/lib/snapd/potato"))
}

func (s *toolSuite) TestInternalToolPathWithOtherLocation(c *C) {
	tmpdir := c.MkDir()
	restore := snapdtool.MockOsReadlink(func(string) (string, error) {
		return filepath.Join(tmpdir, "/tmp/tmp.foo_1234/usr/lib/snapd/snapd"), nil
	})
	defer restore()

	devTool := filepath.Join(tmpdir, "/tmp/tmp.foo_1234/usr/lib/snapd/potato")
	makeFakeExe(c, devTool)

	path, err := snapdtool.InternalToolPath("potato")
	c.Check(err, IsNil)
	c.Check(path, Equals, tmpdir+"/tmp/tmp.foo_1234/usr/lib/snapd/potato")
}

func (s *toolSuite) TestInternalToolSnapPathWithOtherLocation(c *C) {
	tmpdir := c.MkDir()
	restore := snapdtool.MockOsReadlink(func(string) (string, error) {
		return filepath.Join(tmpdir, "/tmp/tmp.foo_1234/usr/bin/snap"), nil
	})
	defer restore()

	devTool := filepath.Join(tmpdir, "/tmp/tmp.foo_1234/usr/lib/snapd/potato")
	makeFakeExe(c, devTool)

	path, err := snapdtool.InternalToolPath("potato")
	c.Check(err, IsNil)
	c.Check(path, Equals, tmpdir+"/tmp/tmp.foo_1234/usr/lib/snapd/potato")
}

func (s *toolSuite) TestInternalToolPathWithOtherCrazyLocation(c *C) {
	tmpdir := c.MkDir()
	s.fakeInternalTool(c, filepath.Join(tmpdir, "/usr/foo/usr/tmp/tmp.foo_1234"), "potato")
	restore := snapdtool.MockOsReadlink(func(string) (string, error) {
		return filepath.Join(tmpdir, "/usr/foo/usr/tmp/tmp.foo_1234/usr/bin/snap"), nil
	})
	defer restore()

	path, err := snapdtool.InternalToolPath("potato")
	c.Check(err, IsNil)
	c.Check(path, Equals, tmpdir+"/usr/foo/usr/tmp/tmp.foo_1234/usr/lib/snapd/potato")
}

func (s *toolSuite) TestInternalToolPathWithDevLocationFallback(c *C) {
	restore := snapdtool.MockOsReadlink(func(string) (string, error) {
		return filepath.Join("/home/dev/snapd/snapd"), nil
	})
	defer restore()

	path, err := snapdtool.InternalToolPath("potato")
	c.Check(err, IsNil)
	c.Check(path, Equals, filepath.Join(dirs.DistroLibExecDir, "potato"))
}

func (s *toolSuite) TestInternalToolPathWithOtherDevLocationWhenExecutableFallback(c *C) {
	restore := snapdtool.MockOsReadlink(func(string) (string, error) {
		return filepath.Join(dirs.GlobalRootDir, "/tmp/snapd"), nil
	})
	defer restore()

	devTool := filepath.Join(dirs.GlobalRootDir, "/tmp/potato")
	err := os.MkdirAll(filepath.Dir(devTool), 0755)
	c.Assert(err, IsNil)
	err = os.WriteFile(devTool, []byte(""), 0755)
	c.Assert(err, IsNil)

	path, err := snapdtool.InternalToolPath("potato")
	c.Check(err, IsNil)
	c.Check(path, Equals, filepath.Join(dirs.DistroLibExecDir, "potato"))
}

func (s *toolSuite) TestInternalToolPathWithOtherDevLocationNonExecutable(c *C) {
	restore := snapdtool.MockOsReadlink(func(string) (string, error) {
		return filepath.Join(dirs.GlobalRootDir, "/tmp/snapd"), nil
	})
	defer restore()

	devTool := filepath.Join(dirs.GlobalRootDir, "/tmp/potato")
	makeFakeExe(c, devTool)

	path, err := snapdtool.InternalToolPath("non-executable-potato")
	c.Check(err, IsNil)
	c.Check(path, Equals, filepath.Join(dirs.DistroLibExecDir, "non-executable-potato"))
}

func (s *toolSuite) TestInternalToolPathSnapdPathReexec(c *C) {
	s.fakeInternalTool(c, filepath.Join(dirs.SnapMountDir, "core/111"), "snapd")
	restore := snapdtool.MockOsReadlink(func(string) (string, error) {
		return filepath.Join(dirs.SnapMountDir, "core/111/usr/bin/snap"), nil
	})
	defer restore()

	p, err := snapdtool.InternalToolPath("snapd")
	c.Assert(err, IsNil)
	c.Check(p, Equals, filepath.Join(dirs.SnapMountDir, "/core/111/usr/lib/snapd/snapd"))
}

func (s *toolSuite) TestInternalToolPathSnapdSnap(c *C) {
	s.fakeInternalTool(c, filepath.Join(dirs.SnapMountDir, "snapd/22"), "snapd")
	restore := snapdtool.MockOsReadlink(func(string) (string, error) {
		return filepath.Join(dirs.SnapMountDir, "snapd/22/usr/bin/snap"), nil
	})
	defer restore()

	p, err := snapdtool.InternalToolPath("snapd")
	c.Assert(err, IsNil)
	c.Check(p, Equals, filepath.Join(dirs.SnapMountDir, "/snapd/22/usr/lib/snapd/snapd"))
}

func (s *toolSuite) TestInternalToolPathSnapdSnapNotExecutable(c *C) {
	snapdMountDir := filepath.Join(dirs.SnapMountDir, "snapd/22")
	snapdSnapInternalToolPath := filepath.Join(snapdMountDir, "/usr/lib/snapd/snapd")
	s.fakeInternalTool(c, snapdMountDir, "snapd")
	restore := snapdtool.MockOsReadlink(func(string) (string, error) {
		return snapdSnapInternalToolPath, nil
	})
	defer restore()

	// make snapd *not* executable
	c.Assert(os.Chmod(snapdSnapInternalToolPath, 0644), IsNil)

	// Now the internal tool path falls back to the global snapd because
	// the internal one is not executable
	p, err := snapdtool.InternalToolPath("snapd")
	c.Assert(err, IsNil)
	c.Check(p, Equals, filepath.Join(dirs.DistroLibExecDir, "snapd"))
}

func (s *toolSuite) TestInternalToolPathWithLibexecdirLocation(c *C) {
	dirstest.MustMockAltLibExecDir(s.fakeroot)
	dirs.SetRootDir(s.fakeroot)

	restore := snapdtool.MockOsReadlink(func(string) (string, error) {
		return filepath.Join("/usr/bin/snap"), nil
	})
	defer restore()

	path, err := snapdtool.InternalToolPath("potato")
	c.Check(err, IsNil)
	c.Check(dirs.StripRootDir(path), Equals, filepath.Join("/usr/libexec/snapd/potato"))
}

func (s *toolSuite) TestExecInSnapdOrCoreSnap(c *C) {
	defer s.mockReExecFor(c, s.snapdPath, "potato", dirs.DefaultDistroLibexecDir)()

	c.Check(snapdtool.ExecInSnapdOrCoreSnap, PanicMatches, `>exec of "[^"]+/potato" in tests<`)
	c.Check(s.execCalled, Equals, 1)
	c.Check(s.lastExecArgv0, Equals, filepath.Join(s.snapdPath, "/usr/lib/snapd/potato"))
	c.Check(s.lastExecArgv, DeepEquals, os.Args)
}

func (s *toolSuite) TestExecInSnapdOrCoreSnapFixArg0(c *C) {
	defer s.mockReExecFor(c, s.snapdPath, "snapdtool.test", dirs.DefaultDistroLibexecDir)()

	c.Check(snapdtool.ExecInSnapdOrCoreSnap, PanicMatches, `>exec of "[^"]+/snapdtool.test" in tests<`)
	c.Check(s.execCalled, Equals, 1)
	c.Check(s.lastExecArgv0, Equals, filepath.Join(s.snapdPath, "/usr/lib/snapd/snapdtool.test"))
	c.Check(s.lastExecArgv[0], Equals, filepath.Join(s.snapdPath, "/usr/lib/snapd/snapdtool.test"))
	c.Check(s.lastExecArgv[1:], DeepEquals, os.Args[1:])
}

func (s *toolSuite) TestExecInOldCoreSnap(c *C) {
	defer s.mockReExecFor(c, s.corePath, "potato", dirs.DefaultDistroLibexecDir)()

	c.Check(snapdtool.ExecInSnapdOrCoreSnap, PanicMatches, `>exec of "[^"]+/potato" in tests<`)
	c.Check(s.execCalled, Equals, 1)
	c.Check(s.lastExecArgv0, Equals, filepath.Join(s.corePath, "/usr/lib/snapd/potato"))
	c.Check(s.lastExecArgv, DeepEquals, os.Args)
}

func (s *toolSuite) TestExecInSnapdOrCoreSnapBailsNoCoreSupport(c *C) {
	defer s.mockReExecFor(c, s.snapdPath, "potato", dirs.DefaultDistroLibexecDir)()

	// no "info" -> no core support:
	c.Assert(os.Remove(filepath.Join(s.snapdPath, "/usr/lib/snapd/info")), IsNil)

	snapdtool.ExecInSnapdOrCoreSnap()
	c.Check(s.execCalled, Equals, 0)
}

func (s *toolSuite) TestExecInSnapdOrCoreSnapMissingExe(c *C) {
	defer s.mockReExecFor(c, s.snapdPath, "potato", dirs.DefaultDistroLibexecDir)()

	// missing exe:
	c.Assert(os.Remove(filepath.Join(s.snapdPath, "/usr/lib/snapd/potato")), IsNil)

	snapdtool.ExecInSnapdOrCoreSnap()
	c.Check(s.execCalled, Equals, 0)
}

func (s *toolSuite) TestExecInSnapdOrCoreSnapBadSelfExe(c *C) {
	defer s.mockReExecFor(c, s.snapdPath, "potato", dirs.DefaultDistroLibexecDir)()

	// missing self/exe:
	c.Assert(os.Remove(filepath.Join(s.fakeroot, "proc/self/exe")), IsNil)

	snapdtool.ExecInSnapdOrCoreSnap()
	c.Check(s.execCalled, Equals, 0)
}

func (s *toolSuite) TestExecInSnapdOrCoreSnapBailsNoDistroSupport(c *C) {
	snapReexec := os.Getenv("SNAP_REEXEC")
	defer os.Setenv("SNAP_REEXEC", snapReexec)
	err := os.Unsetenv("SNAP_REEXEC")
	c.Assert(err, IsNil)

	defer s.mockReExecFor(c, s.snapdPath, "potato", dirs.DefaultDistroLibexecDir)()

	// no distro support:
	defer release.MockOnClassic(false)()

	snapdtool.ExecInSnapdOrCoreSnap()
	c.Check(s.execCalled, Equals, 0)
}

func (s *toolSuite) TestExecInSnapdOrCoreSnapNoDouble(c *C) {
	selfExe := filepath.Join(s.fakeroot, "proc/self/exe")
	err := os.Symlink(filepath.Join(s.fakeroot, "/snap/core/42/usr/lib/snapd"), selfExe)
	c.Assert(err, IsNil)
	snapdtool.MockSelfExe(selfExe)

	snapdtool.ExecInSnapdOrCoreSnap()
	c.Check(s.execCalled, Equals, 0)
}

func (s *toolSuite) TestExecInSnapdOrCoreSnapDisabled(c *C) {
	defer s.mockReExecFor(c, s.snapdPath, "potato", dirs.DefaultDistroLibexecDir)()

	os.Setenv("SNAP_REEXEC", "0")
	defer os.Unsetenv("SNAP_REEXEC")

	snapdtool.ExecInSnapdOrCoreSnap()
	c.Check(s.execCalled, Equals, 0)
}

func (s *toolSuite) testExecInSnapdOrCoreSnapOnUnsupportedDistro(c *C, libexecDir string) {
	// distro which does not support reexec
	defer release.MockReleaseInfo(&release.OS{ID: "arch"})()

	dirs.SetRootDir(s.fakeroot)
	s.snapdPath = filepath.Join(dirs.SnapMountDir, "/snapd/42")
	s.corePath = filepath.Join(dirs.SnapMountDir, "/core/21")
	defer snapdtool.MockCoreSnapdPaths(s.corePath, s.snapdPath)()

	// set up desired libexecdir
	defer s.mockReExecFor(c, s.snapdPath, "potato", libexecDir)()

	// reexec does not happen
	snapdtool.ExecInSnapdOrCoreSnap()
	c.Check(s.execCalled, Equals, 0)

	// unless explicitly requested through the environment
	os.Setenv("SNAP_REEXEC", "1")
	defer os.Unsetenv("SNAP_REEXEC")

	// in which case we do reexec
	c.Check(snapdtool.ExecInSnapdOrCoreSnap, PanicMatches, `>exec of "[^"]+/potato" in tests<`)
	c.Check(s.execCalled, Equals, 1)
	// and reexec uses the correct mount path
	c.Check(s.lastExecArgv0, Equals, filepath.Join(s.fakeroot, "/var/lib/snapd/snap/snapd/42/usr/lib/snapd/potato"))
	c.Check(s.lastExecArgv, DeepEquals, os.Args)
}

func (s *toolSuite) TestExecInSnapdOrCoreSnapOnUnsupportedDistro(c *C) {
	s.testExecInSnapdOrCoreSnapOnUnsupportedDistro(c, dirs.DefaultDistroLibexecDir)
}

func (s *toolSuite) TestExecInSnapdOrCoreSnapOnUnsupportedDistroAltLibexecdir(c *C) {
	s.testExecInSnapdOrCoreSnapOnUnsupportedDistro(c, dirs.AltDistroLibexecDir)
}

func (s *toolSuite) TestIsReexecd(c *C) {
	mockedSelfExe := filepath.Join(s.fakeroot, "proc/self/exe")
	restore := snapdtool.MockSelfExe(mockedSelfExe)
	defer restore()

	// pretend the binary reexecd from snap mount location
	err := os.Symlink(filepath.Join(s.snapdPath, "usr/lib/snapd/snapd"), mockedSelfExe)
	c.Assert(err, IsNil)

	is, err := snapdtool.IsReexecd()
	c.Assert(err, IsNil)
	c.Assert(is, Equals, true)

	err = os.Remove(mockedSelfExe)
	c.Assert(err, IsNil)
	// now it's not
	err = os.Symlink(filepath.Join(dirs.DistroLibExecDir, "snapd"), mockedSelfExe)
	c.Assert(err, IsNil)

	is, err = snapdtool.IsReexecd()
	c.Assert(err, IsNil)
	c.Assert(is, Equals, false)

	// trouble reading the symlink
	err = os.Remove(mockedSelfExe)
	c.Assert(err, IsNil)

	is, err = snapdtool.IsReexecd()
	c.Assert(err, ErrorMatches, ".*/proc/self/exe: no such file or directory")
	c.Assert(is, Equals, false)
}

func (s *toolSuite) TestInReexecEnabled(c *C) {
	defer os.Unsetenv("SNAP_REEXEC")

	// explicitly disabled
	os.Setenv("SNAP_REEXEC", "0")
	c.Assert(snapdtool.IsReexecEnabled(), Equals, false)
	// default to true
	os.Unsetenv("SNAP_REEXEC")
	c.Assert(snapdtool.IsReexecEnabled(), Equals, true)
	// explicitly enabled
	os.Setenv("SNAP_REEXEC", "1")
	c.Assert(snapdtool.IsReexecEnabled(), Equals, true)
}

func (s *toolSuite) TestExeAndRoot(c *C) {
	mockedSelfExe := filepath.Join(s.fakeroot, "proc/self/exe")
	restore := snapdtool.MockSelfExe(mockedSelfExe)
	defer restore()

	// pretend the binary reexecd from snap mount location
	err := os.Symlink(filepath.Join(s.snapdPath, "usr/lib/snapd/snapd"), mockedSelfExe)
	c.Assert(err, IsNil)

	root, exe, err := snapdtool.ExeAndRoot()
	c.Assert(err, IsNil)
	c.Assert(root, Equals, s.snapdPath)
	c.Assert(exe, Equals, "usr/lib/snapd/snapd")

	err = os.Remove(mockedSelfExe)
	c.Assert(err, IsNil)
	// now it's not
	err = os.Symlink(filepath.Join(dirs.DistroLibExecDir, "snapd"), mockedSelfExe)
	c.Assert(err, IsNil)

	root, exe, err = snapdtool.ExeAndRoot()
	c.Assert(err, IsNil)
	c.Assert(root, Equals, dirs.GlobalRootDir)
	// distro libexecdir without the root part
	noRootPrefix, err := filepath.Rel(dirs.GlobalRootDir, dirs.DistroLibExecDir)
	c.Assert(err, IsNil)
	c.Assert(exe, Equals, filepath.Join(noRootPrefix, "snapd"))

	// trouble reading the symlink
	err = os.Remove(mockedSelfExe)
	c.Assert(err, IsNil)

	root, exe, err = snapdtool.ExeAndRoot()
	c.Assert(err, ErrorMatches, ".*/proc/self/exe: no such file or directory")
	c.Check(root, Equals, "")
	c.Check(exe, Equals, "")

	err = os.Symlink(filepath.Join(dirs.SnapMountDir, "abc/def"), mockedSelfExe)
	c.Assert(err, IsNil)
	root, exe, err = snapdtool.ExeAndRoot()
	c.Check(err, ErrorMatches, `cannot parse snap tool path ".*/snap/abc/def"`)
	c.Check(root, Equals, "")
	c.Check(exe, Equals, "")
}
