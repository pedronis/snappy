# Hacking on snapd

Hacking on `snapd` is fun and straightforward. The code is extensively unit
tested and we use the [spread](https://github.com/snapcore/spread)
integration test framework for the integration/system level tests.

For non-technical details on contributing to the project, including how to
approach a pull request, see [Contributing to snapd](./CONTRIBUTING.md).

## Setting up

### Supported Ubuntu distributions

Ubuntu 18.04 LTS or later is recommended for `snapd` development.
Usually, the latest LTS would be the best choice.

> If you want to build or test on older versions of Ubuntu, additional steps
may be required when installing dependencies.

### Supported Go version

Go 1.18 (or later) is required to build `snapd`.

> If you need to build older versions of snapd, please have a look at the file
[debian/control](debian/control) to find out what dependencies were needed at the time
(including which version of the Go compiler).

### Getting the snapd sources

The easiest way to get the source for `snapd` is to clone the GitHub repository
in a directory where you have read-write permissions, such as your home
directory.

    cd ~/
    git clone https://github.com/snapcore/snapd.git
    cd snapd

This will allow you to build and test `snapd`. If you wish to contribute to
the `snapd` project, please see [Contributing to snapd](./CONTRIBUTING.md).

> For more details about source-code structure of `snapd` please read about
[Managing module source](https://go.dev/doc/modules/managing-source) in Go.

### Installing the build dependencies

Build dependencies can automatically be resolved using `build-dep` on Ubuntu:

    cd ~/snapd
    sudo apt build-dep .

Package build dependencies for other distributions can be found under the
[./packaging/](./packaging/) directory. Eg. for Fedora use:

    cd packaging/fedora
    sudo dnf install -y rpmdevtools
    sudo dnf install -y $(rpmspec -q --buildrequires snapd.spec)
    sudo dnf install glibc-static.i686 glibc-devel.i686

Source dependencies are automatically retrieved at build time.
Sometimes, it might be useful to pull them without building:

```
cd ~/snapd
go get ./... && ./get-deps.sh
```

## Building

### Building the snap with snapcraft

The easiest (though not the most efficient) way to test changes to snapd is to
build the snapd snap using _snapcraft_ and then install that snapd snap. The
[snapcraft.yaml](./build-aux/snap/snapcraft.yaml) for the snapd snap is located at
[./build-aux/](./build-aux/), and
can be built using snapcraft.

Snapcraft 8.x or later is expected.

Install snapcraft:

```
sudo snap install snapcraft --classic
```

Install and init lxd:

```
sudo snap install lxd
sudo lxd init --minimal
```

Then run snapcraft:

```
snapcraft
```

Now the snapd snap that was just built can be installed with:

```
sudo snap install --dangerous snapd_*.snap
```

To go back to using snapd from the store instead of the custom version we 
installed (since it will not get updates as it was installed dangerously), you
can either use `snap revert snapd`, or you can refresh directly with 
`snap refresh snapd --stable --amend`.

#### Building for other architectures with snapcraft

It is also sometimes useful to use snapcraft to build the snapd snap for
other architectures using the `remote-build` feature.

You can use remote-build with snapcraft on the snapd tree for any desired
architectures:

```
snapcraft remote-build --build-for=armhf,s390x,arm64
```

#### Splicing the snapd snap into the core snap

Sometimes while developing you may need to build a version of the _core_ snap
with a custom snapd version. 
The `snapcraft.yaml` for the [core snap](https://github.com/snapcore/core/) 
currently is complex in that it assumes it is built inside Launchpad with the 
[ppa:snappy-dev/image](https://launchpad.net/~snappy-dev/+archive/ubuntu/image/) 
enabled, so it is difficult to inject a custom version of
snapd into this by rebuilding the core snap directly, so an easier way is to 
actually first build the snapd snap and inject the binaries from the snapd snap
into the core snap. This currently works since both the snapd snap and the core 
snap have the same `build-base` of Ubuntu 16.04. However, at some point in time
this trick will stop working when the snapd snap starts using a `build-base` other
than Ubuntu 16.04, but until then, you can use the following trick to more 
easily get a custom version of snapd inside a core snap.

First follow the steps above to build a full snapd snap. Then, extract the core
snap you wish to splice the custom snapd snap into:

```
sudo unsquashfs -d custom-core core_<rev>.snap
```

`sudo` is important as the core snap has special permissions on various 
directories and files that must be preserved as it is a boot base snap.

Now, extract the snapd snap, again with sudo because there are `suid` binaries
which must retain their permission bits:

```
sudo unsquashfs -d custom-snapd snapd-custom.snap
```

Now, copy the meta directory from the core snap outside to keep it and prevent
it from being lost when we replace the files from the snapd snap:

```
sudo cp ./custom-core/meta meta-core-backup
```

Then copy all the files from the snapd snap into the core snap, and delete the
meta directory so we don't use any of the meta files from the snapd snap:

```
sudo cp -r ./custom-snapd/* ./custom-core/
sudo rm -r ./custom-core/meta/
sudo cp ./meta-core-backup ./custom-core/
```

Now we can repack the core snap:

```
sudo snap pack custom-core
```

Sometimes it is helpful to modify the snap version in 
`./custom-core/meta/snap.yaml` before repacking with `snap pack` so it is easy
to identify which snap file is which.

### Building natively

To build the `snap` command line client:

```
cd ~/snapd
mkdir -p /tmp/build
go build -o /tmp/build/snap ./cmd/snap
```

To build the `snapd` REST API daemon:

```
cd ~/snapd
mkdir -p /tmp/build
go build -o /tmp/build/snapd ./cmd/snapd
```

To build all the `snapd` Go components:

```
cd ~/snapd
mkdir -p /tmp/build
go build -o /tmp/build ./...
```

### Building with cross-compilation (_example: ARM v7 target_)

Install a suitable cross-compiler for the target architecture.

```
sudo apt-get install gcc-arm-linux-gnueabihf
```

Verify the default architecture version of your GCC cross-compiler.

```
arm-linux-gnueabihf-gcc -v
:
--with-arch=armv7-a
--with-fpu=vfpv3-d16
--with-float=hard
--with-mode=thumb
```

Verify the supported Go cross-compile ARM targets [here](
https://github.com/golang/go/wiki/GoArm).

`Snapd` depends on [libseccomp](https://github.com/seccomp/libseccomp#readme) 
v2.3 or later. The following instructions can be
used to cross-compile the library:

```
cd ~/
git clone https://github.com/seccomp/libseccomp
cd libseccomp
./autogen.sh
./configure --host=arm-linux-gnueabihf --prefix=${HOME}/libseccomp/build
make && make install
```

Setup the Go environment for cross-compiling.

```sh
export CC=arm-linux-gnueabihf-gcc
export CGO_ENABLED=1
export CGO_LDFLAGS="-L${HOME}/libseccomp/build/lib"
export GOOS=linux
export GOARCH=arm
export GOARM=7
```

The Go environment variables are now explicitly set to target the ARM v7
architecture.

Run the same build commands from the Building (natively) section above.

Verify the target architecture by looking at the application ELF header.

```
readelf -h /tmp/build/snapd
:
Class:                             ELF32
OS/ABI:                            UNIX - System V
Machine:                           ARM
```

CGO produced ELF binaries contain additional architecture attributes that
reflect the exact ARM architecture we targeted.

```
readelf -A /tmp/build/snap-seccomp
:
File Attributes
  Tag_CPU_name: "7-A"
  Tag_CPU_arch: v7
  Tag_FP_arch: VFPv3-D16
```

## Testing

We value good tests, so when you fix a bug or add a new feature we highly
encourage you to add tests.

Install the following package(s) to satisfy test dependencies.

```
sudo apt-get install python3-yamlordereddictloader dbus-x11
```

### Running unit-tests

To run the various tests that we have to ensure a high quality source just run:

    ./run-checks

This will check if the source format is consistent, that it builds, all tests
work as expected and that "go vet" has nothing to complain about.

The source format follows the `gofmt -s` formating. Please run this on your 
source files if `run-checks` complains about the format.

You can run an individual test for a sub-package by changing into that 
directory and:

```
go test -check.f $testname
```

If a test hangs, you can enable verbose mode:

```
go test -v -check.vv
```

Or, try just `-check.v` for a less verbose output.

> Some unit tests are known to fail on locales other than `C.UTF-8`. 
If you have unit tests failing, try setting `LANG=C.UTF-8` when running 
`go test`. See [issue #1960131](https://bugs.launchpad.net/snapd/+bug/1960131) for more details.

There is more to read about the testing framework on the [website](https://labix.org/gocheck)

### Running integration tests

#### Downloading spread framework

To run the integration tests locally via QEMU, you need the latest version of
the [spread](https://github.com/snapcore/spread) framework. For local testing
you can install the `image-garden` snap that comes with pre-built releases of
upstream spread, qemu and all the support tools. Alternatively you may install
[image-garden](https://gitlab.com/zygoon/image-garden) from source or from a
distribution package.

To install `image-garden` as a snap run `sudo snap install image-garden`. To
use the bundled copy of spread from image-garden separately run `sudo snap
alias image-garden.spread spread`.

#### Running spread

For regular development work, the integration tests will be run with a prebuilt
test variant of the snapd snap. The build happens automatically when starting
the tests using `run-spread` helper like so:

    $ ./run-spread <spread-args>

Make sure you set up snapcraft following the [snapcraft build
section](#building-the-snap-with-snapcraft).

The test variant of the snapd snap may be built manually by invoking a helper
script:

    $ ./tests/build-test-snapd-snap
    
The artifact will be placed under `$PWD/built-snap`.

On occasion, when working on a test and it is known that the snapd snap need not
be rebuilt, the tests may be invoked with `NO_REBUILD=1` like so:

    $ NO_REBUILD=1 ./run-spread <spread-args>

#### Running spread without a cloud account

You can run most of the tests locally, using the `garden` backend. For example,
to run integration tests for Ubuntu 18.04 LTS 64-bit, invoke spread as follows:

    $ ./run-spread -v garden:ubuntu-18.04-64

> Look at the `spread.yaml` file for a list of systems that are supported by
> the garden backend.

The `garden` backend automatically downloads and initializes each base system.
During testing additional scratch space is used to hold ephemeral chances to
the disk image. This may require significant amount of space in `/tmp` so if
your system uses `tmpfs` in `/tmp` you may want look at available free space.
This especially affects the snap version of `image-garden`, as snap
packages cannot use `/var/tmp` for scratch space.

For quick reuse you can use:

    $ ./run-spread -reuse garden:ubuntu-18.04-64

It will print how to reuse the systems. Make sure to use
`export REUSE_PROJECT=1` in your environment too.

### Testing the snapd daemon

To test the `snapd` REST API daemon on a snappy system you need to
transfer it to the snappy system and then run:

    sudo systemctl stop snapd.service snapd.socket
    sudo SNAPD_DEBUG=1 SNAPD_DEBUG_HTTP=3 ./snapd

To debug interaction with the snap store, you can set `SNAPD_DEBUG_HTTP`.
It is a bitfield: dump requests: 1, dump responses: 2, dump bodies: 4.

Similarly, to debug the interaction between the `snap` command-line tool and the
snapd REST API, you can set `SNAP_CLIENT_DEBUG_HTTP`. It is also a bitfield,
with the same values and behaviour as `SNAPD_DEBUG_HTTP`.
> In case you get some security profiles errors, when trying to install or refresh a snap, 
maybe you need to replace system installed snap-seccomp with the one aligned to the snapd that 
you are testing. To do this, simply backup `/usr/lib/snapd/snap-seccomp` and overwrite it with 
the testing one. Don't forget to roll back to the original, after you finish testing.

### Testing the snap userd agent

To test the `snap userd --agent` command, you must first stop the current process, if it is
running, and then stop the dbus activation part. To do so, just run:

    systemctl --user disable snapd.session-agent.socket
    systemctl --user stop snapd.session-agent.socket

After that, it's now possible to launch the daemon with `snapd userd --agent` from a command
line.

To re-enable the dbus activation, kill that process and run:

    systemctl --user enable snapd.session-agent.socket

### Running nested tests

Nested tests are used to validate features that cannot be tested with the regular tests.

The nested test suites work differently from the other test suites in snapd. In
this case each test runs in a new image which is created following the rules
defined for the test.

The nested tests are executed using the [spread framework](#downloading-spread-framework). 
See the following examples using the QEMU and Google backends.

- _QEMU_: `spread qemu-nested:ubuntu-20.04-64:tests/nested/core20/tpm`  
- _Google_: `spread google-nested:ubuntu-20.04-64:tests/nested/core20/tpm`  

The nested system in all the cases is selected based on the host system. The following lines 
show the relation between host and nested `systemd` (same applies to the classic nested tests):

- ubuntu-16.04-64 => ubuntu-core-16-64
- ubuntu-18.04-64 => ubuntu-core-18-64
- ubuntu-20.04-64 => ubuntu-core-20-64

The tools used for creating and hosting the nested VMs are:

- _ubuntu-image snap_ is used to build the images
- _QEMU_ is used for the virtualization (with [_KVM_](https://www.linux-kvm.org/page/Main_Page) acceleration)

Nested test suite is composed by the following 4 suites:

- _classic_: the nested suite contains an image of a classic system downloaded from cloud-images.ubuntu.com 
- _core_: it tests a core nested system, and the images are generated with _ubuntu-image snap_
- _core20_: this is similar to the _core_ suite, but these tests are focused on UC20
- _manual_: tests on this suite create a non generic image with specific conditions

The nested suites use some environment variables to configure the suite 
and the tests inside it. The most important ones are described below:

- `NESTED_WORK_DIR`: path to the directory where all the nested assets and images are stored
- `NESTED_TYPE`: use core for Ubuntu Core nested systems or classic instead.
- `NESTED_CORE_CHANNEL`: the images are created using _ubuntu-image snap_, use it to define the default branch
- `NESTED_CORE_REFRESH_CHANNEL`: the images can be refreshed to a specific channel; use it to specify the channel
- `NESTED_USE_CLOUD_INIT`: use cloud init to make initial system configuration instead of user assertion
- `NESTED_ENABLE_KVM`: enable KVM in the QEMU command line
- `NESTED_ENABLE_TPM`: re-boot in the nested VM in case it is supported (just supported on UC20)
- `NESTED_ENABLE_SECURE_BOOT`: enable secure boot in the nested VM in case it is supported (supported just on UC20)
- `NESTED_BUILD_SNAPD_FROM_CURRENT`: build and use either core or `snapd` from the current branch
- `NESTED_CUSTOM_IMAGE_URL`: download and use an custom image from this URL
- `NESTED_SNAPD_DEBUG_TO_SERIAL`:  add snapd debug and log to nested vm serial console
- `NESTED_EXTRA_CMDLINE`:  add any extra cmd line parameter to the nested vm

# Quick intro to hacking on snap-confine

Hey, welcome to the nice, low-level world of snap-confine

## Building the code locally

To get started from a pristine tree you want to do this:

```
./mkversion.sh
cd cmd/
autoreconf -i -f
./configure --prefix=/usr --libexecdir=/usr/lib/snapd --enable-nvidia-multiarch --with-host-arch-triplet="$(dpkg-architecture -qDEB_HOST_MULTIARCH)"
```

This will drop makefiles and let you build stuff. You may find the `make hack`
target, available in [./cmd/](./cmd/) handy `(cd cmd; make hack)`. It installs the locally built
version on your system and reloads the [AppArmor](https://apparmor.net/) profile.

>The above configure options assume you are on Ubuntu and are generally
necessary to run/test graphical applications with your local version of
snap-confine. The `--with-host-arch-triplet` option sets your specific 
architecture and `--enable-nvidia-multiarch` allows the host's graphics drivers
and libraries to be shared with snaps. If you are on a distro other than
Ubuntu, try `--enable-nvidia-biarch` (though you'll likely need to add further
system-specific options too).

## Testing your changes locally 

After building the code locally as explained in the previous section, you can run the 
test suite available for snap-confine (among other low-level tools) by running the 
`make check` target available in [./cmd]((./cmd/)).

## Submitting patches

Please run `(cd cmd; make fmt)` before sending your patches for the "C" part of
the source code.

<!-- !TODO: Few things to clean up in the future:

[] Add a section that describes functional labels in GitHub that we use to influence the verification flow of the PR
[] Remove reference to https://bugs.launchpad.net/snapd/+bug/1960131 once it gets fixed

//-->
