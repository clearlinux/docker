// +build linux

package clr

import (
	"crypto/sha512"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"math"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"

	"github.com/Sirupsen/logrus"
	"github.com/docker/docker/daemon/execdriver"
	"github.com/docker/docker/pkg/mount"
	sysinfo "github.com/docker/docker/pkg/system"
	"github.com/docker/docker/pkg/term"
	"github.com/docker/libnetwork/netlabel"
	"github.com/kr/pty"
	"github.com/opencontainers/runc/libcontainer/configs"
)

const (
	// Clear Linux for Intel(R) Architecture
	driverName = "clr"

	envVarPrefix = "CLR_"

	// variable that allows clrURL to be modified
	clrEnvURL = envVarPrefix + "DOWNLOAD_URL"

	// Command used for lkvm control
	lkvmName = "lkvm"

	// default value for clrURL
	defaultClrURL = "https://download.clearlinux.org"

	// upstream latest release file (found below clrURL)
	latestFile = "latest"

	// local "latest" information
	clrFile = "latest"

	// ASCII file containing a checksums for the downloaded image.
	clrChecksumFile = "SHA512SUMS"

	// clr kernel (not bzimage)
	clrKernel = "/usr/lib/kernel/vmlinux.container"
)

var (
	// upstream base URL
	clrURL = defaultClrURL
)

type driver struct {
	root             string // root path for the driver to use
	libPath          string
	initPath         string
	version          string
	apparmor         bool
	sharedRoot       bool
	activeContainers map[string]*activeContainer
	machineMemory    int64
	containerPid     int
	sync.Mutex
	ipaddr  string
	gateway string
	macaddr string
}

type activeContainer struct {
	container *configs.Config
	cmd       *exec.Cmd
}

type ProgressReader struct {
	// The real reader
	io.Reader

	// Total size of download
	total uint64

	// Bytes received
	bytes uint64

	// Rate-limiting counter
	lastShown int

	rawURL string
}

// Read implements the Reader interface by calling the _real_ reader
// and periodically displaying progress information.
func (r *ProgressReader) Read(p []byte) (n int, err error) {
	n, err = r.Reader.Read(p)

	if err != nil && err != io.EOF {
		// A true error occured
		return n, err
	}

	r.bytes += uint64(n)

	if r.total == 0 {
		// http header did not provide size
		logrus.Debugf("Read %v bytes from %v", r.bytes, r.rawURL)
	} else {
		percent := (float64(r.bytes) / float64(r.total)) * 100

		// rate-limit to only display messages for every 10% downloaded
		next := int(percent / 10)

		if r.lastShown == -1 || next > r.lastShown {
			logrus.Debugf("Read %v of %v bytes from %v (%2.2f%%)", r.bytes, r.total, r.rawURL, percent)
			r.lastShown = next
		}
	}

	return n, err
}

func getTapIf(c *execdriver.Command) string {
	return fmt.Sprintf("tb-%s", c.ID[:12])
}

// getClrVersion reads the latest image version from the
// locally-downloaded "latest" file.
func getClrVersion(libPath string) string {
	txt, err := ioutil.ReadFile(path.Join(libPath, clrFile))
	if err != nil {
		return ""
	}
	return strings.Split(string(txt), "\n")[0]
}

func getURL(rawURL, outfile string) error {

	_url, err := url.Parse(rawURL)
	if err != nil {
		return err
	}

	out, err := os.Create(outfile)
	if err != nil {
		return err
	}
	defer out.Close()

	transport := &http.Transport{Proxy: http.ProxyFromEnvironment}
	client := &http.Client{Transport: transport}

	// Determine size of download by consulting the headers
	response, err := client.Head(rawURL)
	if err != nil {
		return err
	}

	lenStr := response.Header.Get("Content-Length")
	dataLen, _ := strconv.Atoi(lenStr)

	request, err := http.NewRequest("GET", _url.String(), nil)
	if err != nil {
		return err
	}

	response, err = client.Do(request)
	defer response.Body.Close()

	reader := &ProgressReader{
		Reader:    response.Body,
		total:     uint64(dataLen),
		lastShown: -1,
		rawURL:    rawURL,
	}

	_, err = io.Copy(out, reader)

	return err
}

// fetchLatest downloads the "latest" file which contains the version
// number of the latest image.
func fetchLatest(libPath string) error {
	file := path.Join(libPath, clrFile)
	return getURL(clrURL+"/"+latestFile, file)
}

// NewDriver creates a new clear linux execution driver.
func NewDriver(root, libPath, initPath string, apparmor bool) (*driver, error) {
	if err := os.MkdirAll(root, 0700); err != nil {
		return nil, err
	}
	meminfo, err := sysinfo.ReadMemInfo()
	if err != nil {
		return nil, err
	}
	version, err := prepareClr(libPath)
	if err != nil {
		return nil, err
	}

	return &driver{
		apparmor:         apparmor,
		root:             root,
		libPath:          libPath,
		initPath:         initPath,
		version:          version,
		sharedRoot:       false,
		activeContainers: make(map[string]*activeContainer),
		// FIXME:
		machineMemory: meminfo.MemTotal,
	}, nil
}

// fetchImage downloads the latest image and verifies its checksum.
func fetchImage(version, outfile, outpath string) error {

	url := fmt.Sprintf("%s/releases/%s/clear/%s", clrURL, version, outfile)

	logrus.Debugf("Fetching clr version: %s, %s", version, outpath)

	return getURL(url, outpath)
}

// uncompressImage handles decompressing the image specified by path.
func uncompressImage(path string) error {
	// decompress the file
	cmd := exec.Command("unxz", path)
	cmd.Dir = filepath.Dir(path)

	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("Unable to extract image %s: %s", path, output)
	}

	return nil
}

// getChecksumLine reads the file specified and returns the checksum for
// the filename specified.
func getChecksumLine(file string, filename string) string {
	data, err := ioutil.ReadFile(file)
	if err != nil {
		return ""
	}

	lines := strings.Split(string(data), "\n")

	for _, line := range lines {
		if strings.HasSuffix(line, filename) {
			fields := strings.Fields(line)
			if len(fields) == 2 {
				return fields[0]
			}
		}
	}

	return ""
}

// getChecksum downloads the checksum file for the image version specified,
// storing it under libPath, then extracts the checksum corresponding to
// imageFile and returns it.
func getChecksum(version string, libPath string, imageFile string) (string, error) {
	outfile := path.Join(libPath, clrChecksumFile)
	checkurl := fmt.Sprintf("%s/releases/%s/clear/%s", clrURL, version, clrChecksumFile)

	err := getURL(checkurl, outfile)
	if err != nil {
		return "", err
	}

	// Now, extract the checksum from the downloaded file.
	return getChecksumLine(outfile, imageFile), nil
}

func verifyChecksum(fullPath, expectedChecksum string) error {

	if expectedChecksum == "" {
		return errors.New("blank expectedChecksum")
	}
	if fullPath == "" {
		return errors.New("blank path")
	}

	data, err := ioutil.ReadFile(fullPath)
	if err != nil {
		return err
	}

	calculatedChecksum := fmt.Sprintf("%x", sha512.Sum512(data))

	if calculatedChecksum != expectedChecksum {
		return fmt.Errorf("Checksum mismatch: %v %v", calculatedChecksum, expectedChecksum)
	}

	logrus.Debugf("Checksum for %v correct: %v", fullPath, expectedChecksum)

	return nil
}

// alreadyDownloaded determines if the uncompressed version of the file
// specified by outpath already exists and seems sane.
func alreadyDownloaded(outpath string) bool {
	// strip off the (first) extension
	base := path.Base(outpath)
	extension := filepath.Ext(base)

	uncompressed := strings.TrimSuffix(outpath, extension)

	st, err := os.Stat(uncompressed)

	if err != nil {
		return false
	}

	if st.IsDir() {
		return false
	}

	if st.Size() == 0 {
		return false
	}

	return true
}

// prepareClr handles downloading and checking clr images, returning the
// version of clr that will be used.
func prepareClr(libPath string) (string, error) {
	logrus.Debugf("%s preparing environment", driverName)

	tmp := os.Getenv(clrEnvURL)
	if tmp != "" {
		clrURL = tmp
		logrus.Debugf("%s using alternate download URL: %s", driverName, clrURL)
	}

	var version = getClrVersion(libPath)

	err := fetchLatest(libPath)
	if err != nil {
		return "", err
	}

	nversion := getClrVersion(libPath)
	if nversion == "" {
		return "", errors.New("unable to determine latest clr version")
	}

	outfile := fmt.Sprintf("clear-%s-containers.img.xz", nversion)
	outpath := path.Join(libPath, outfile)

	// If the download originally failed, there may be a partial .xz
	// file. However, this will be ignored and a new download triggered
	// since we only only check for the uncompressed file (which would
	// only exist if the download was successful).
	if alreadyDownloaded(outpath) && nversion == version {
		logrus.Debugf("Using clr version: %s", nversion)
		return nversion, nil
	}

	// Determine the expected checksum for the file about to be
	// downloaded.
	checksum, err := getChecksum(nversion, libPath, outfile)
	if err != nil {
		return "", err
	}

	if nversion != version && version != "" {
		logrus.Debugf("Updating to clr version: %s", nversion)
	} else if version == "" {
		logrus.Debugf("Installing clr version: %s", nversion)
	}

	err = fetchImage(nversion, outfile, outpath)
	if err != nil {
		return "", err
	}

	if err = verifyChecksum(outpath, checksum); err != nil {
		return "", err
	}

	err = uncompressImage(outpath)
	if err != nil {
		return "", err
	}

	return nversion, nil
}

func (d *driver) Name() string {
	return fmt.Sprintf("%s-%s", driverName, d.version)
}

func (d *driver) Run(c *execdriver.Command, pipes *execdriver.Pipes, hooks execdriver.Hooks) (execdriver.ExitStatus, error) {
	var (
		term execdriver.Terminal
		err  error
	)

	container, err := d.createContainer(c)
	if err != nil {
		return execdriver.ExitStatus{ExitCode: -1}, err
	}

	memoryMiB := c.HostConfig.Memory
	if memoryMiB == 0 {
		memoryMiB = 1024
	} else {
		// docker passes the value as bytes
		memoryMiB = memoryMiB / int64(math.Pow(2, 20))
	}

	workingDirVar := fmt.Sprintf("%s%s=%q", envVarPrefix, "WORKINGDIR", c.WorkingDir)
	c.ProcessConfig.Cmd.Env = append(c.ProcessConfig.Cmd.Env, workingDirVar)

	userVar := fmt.Sprintf("%s%s=%q", envVarPrefix, "USER", c.ProcessConfig.User)
	c.ProcessConfig.Cmd.Env = append(c.ProcessConfig.Cmd.Env, userVar)

	if err := d.setupNetwork(c); err != nil {
		return execdriver.ExitStatus{ExitCode: -1}, err
	}

	if c.ProcessConfig.Tty {
		term, err = NewTtyConsole(&c.ProcessConfig, pipes)
	} else {
		term, err = execdriver.NewStdConsole(&c.ProcessConfig, pipes)
	}
	if err != nil {
		return execdriver.ExitStatus{ExitCode: -1}, err
	}
	c.ProcessConfig.Terminal = term

	d.Lock()
	d.activeContainers[c.ID] = &activeContainer{
		container: container,
		cmd:       &c.ProcessConfig.Cmd,
	}
	d.Unlock()

	if err := d.generateEnvConfig(c); err != nil {
		return execdriver.ExitStatus{ExitCode: -1}, err
	}

	if err := d.generateDockerInit(c); err != nil {
		return execdriver.ExitStatus{ExitCode: -1}, err
	}

	for _, m := range c.Mounts {
		dest := path.Join(c.Rootfs, m.Destination)

		if m.Destination == "/etc/hostname" {
			continue
		}

		if !pathExists(m.Source) {
			continue
		}

		opts := "bind"

		if m.Private {
			opts = opts + ",rprivate"
		}
		if m.Slave {
			opts = opts + ",rslave"
		}

		// This may look racy, but it isn't since the VM isn't
		// running yet.
		//
		// The check is necessary to handle bind mounting of
		// regular files correctly since without it we may be
		// attempting to create a directory where there already
		// exists a normal file.
		if !pathExists(dest) {
			if err := os.MkdirAll(dest, 0750); err != nil {
				return execdriver.ExitStatus{ExitCode: -1}, err
			}
		}

		if err := mount.Mount(m.Source, dest, "", opts); err != nil {
			return execdriver.ExitStatus{ExitCode: -1}, err
		}

		if !m.Writable {
			if err := mount.Mount("", dest, "", "bind,remount,ro"); err != nil {
				return execdriver.ExitStatus{ExitCode: -1}, err
			}
		}
		defer mount.Unmount(dest)
	}

	var args []string
	// various things for lkvm
	ifname := getTapIf(c)
	// FIXME: Should be real hostname from like process/container struct
	hostname := c.ID[0:12]
	img := fmt.Sprintf("%s/clear-%s-containers.img", d.libPath, d.version)
	memory := fmt.Sprintf("%d", memoryMiB)
	// FIXME: Locked cores to 6 ?
	cores := fmt.Sprintf("%d", 6)

	args = append(args, c.ProcessConfig.Entrypoint)
	args = append(args, c.ProcessConfig.Arguments...)

	rootParams := fmt.Sprintf("root=/dev/plkvm0p1 rootfstype=ext4 rootflags=dax,data=ordered "+
		"init=/usr/lib/systemd/systemd systemd.unit=container.target rw tsc=reliable "+
		"systemd.show_status=false "+
		"no_timer_check rcupdate.rcu_expedited=1 console=hvc0 quiet ip=%s::%s::%s::off",
		d.ipaddr, d.gateway, hostname)

	params := []string{
		lkvmName, "run", "-c", cores, "-m", memory,
		"--name", c.ID, "--console", "virtio",
		"--kernel", clrKernel,
		"--params", rootParams,
		"--shmem", fmt.Sprintf("0x200000000:0:file=%s:private", img),
		"--network", fmt.Sprintf("mode=tap,script=none,tapif=%s,guest_mac=%s", ifname, d.macaddr),
		"--9p", fmt.Sprintf("%s,rootfs", c.Rootfs),
	}

	logrus.Debugf("%s params %s", driverName, params)
	var (
		name = params[0]
		arg  = params[1:]
	)
	aname, err := exec.LookPath(name)
	if err != nil {
		aname = name
	}
	c.ProcessConfig.Path = aname
	c.ProcessConfig.Args = append([]string{name}, arg...)
	c.ProcessConfig.Env = []string{fmt.Sprintf("HOME=%s", d.root)}

	// Start the container. Since it runs synchronously, we don't Wait()
	// for it since we need to check the status to determine if it did
	// actually start successfully.
	if err := c.ProcessConfig.Start(); err != nil {
		return execdriver.ExitStatus{ExitCode: -1}, err
	}

	var (
		waitErr  error
		waitLock = make(chan struct{})
	)
	go func() {
		if err := c.ProcessConfig.Wait(); err != nil {
			if _, ok := err.(*exec.ExitError); !ok { // Do not propagate the error if it's simply a status code != 0
				waitErr = err
			}
		}
		close(waitLock)
	}()

	// FIXME: need to create state.json for Stats() to work.
	pid := c.ProcessConfig.Process.Pid
	c.ContainerPid = pid
	d.containerPid = pid

	if hooks.Start != nil {
		logrus.Debugf("Invoking startCallback")
		chOOM := make(chan struct{})
		close(chOOM)
		hooks.Start(&c.ProcessConfig, pid, chOOM)
	}

	// FIXME:
	oomKill := false

	// Wait for the VM to shutdown
	<-waitLock
	exitCode := getExitCode(c)

	cExitStatus, cerr := d.cleanupVM(c)

	if cerr != nil {
		waitErr = cerr
		exitCode = cExitStatus
	}

	// check oom error
	if oomKill {
		exitCode = 137
	}

	return execdriver.ExitStatus{ExitCode: exitCode, OOMKilled: false}, waitErr
}

func pathExists(path string) bool {
	if _, err := os.Stat(path); err == nil {
		return true
	}

	return false
}

func pathExecutable(path string) bool {
	s, err := os.Stat(path)
	if err != nil {
		return false
	}

	mode := s.Mode()
	if mode&0111 != 0 {
		return true
	}
	return false
}

func (d *driver) cleanupVM(c *execdriver.Command) (exitStatus int, err error) {
	cmd := exec.Command("ip", "tuntap", "del", "dev", getTapIf(c), "mode", "tap")
	var output []byte

	if output, err = cmd.CombinedOutput(); err != nil {
		if exitError, ok := err.(*exec.ExitError); ok {
			waitStatus := exitError.Sys().(syscall.WaitStatus)
			exitStatus = waitStatus.ExitStatus()
		}
		logrus.Debugf("teardown failed for vm %s: %s (%s)", c.ID, string(output), err.Error())
	}

	// doesn't matter if this fails
	// lkvm could have removed it, and stale sockets are not fatal
	_ = os.Remove(fmt.Sprintf("%s/.lkvm/%s.sock", d.root, c.ID))

	return exitStatus, err
}

// createContainer populates and configures the container type with the
// data provided by the execdriver.Command
func (d *driver) createContainer(c *execdriver.Command) (*configs.Config, error) {
	return execdriver.InitContainer(c), nil
}

/// Return the exit code of the process
// if the process has not exited -1 will be returned
func getExitCode(c *execdriver.Command) int {
	if c.ProcessConfig.ProcessState == nil {
		return -1
	}
	return c.ProcessConfig.ProcessState.Sys().(syscall.WaitStatus).ExitStatus()
}

func (d *driver) lkvmCommand(c *execdriver.Command, arg string) ([]byte, error) {
	args := append([]string{lkvmName}, arg)
	if c != nil {
		args = append(args, "--name", c.ID)
	}
	cmd := exec.Command(lkvmName, args...)
	cmd.Env = []string{fmt.Sprintf("HOME=%s", d.root)}
	return cmd.Output()
}

// Kill sends a signal to workload
func (d *driver) Kill(c *execdriver.Command, sig int) error {
	// Not supported
	return nil
}

func (d *driver) Pause(c *execdriver.Command) error {
	_, err := d.lkvmCommand(c, "pause")
	return err
}

func (d *driver) Unpause(c *execdriver.Command) error {
	_, err := d.lkvmCommand(c, "resume")
	return err
}

// Terminate forcibly stops a container
func (d *driver) Terminate(c *execdriver.Command) error {
	_, err := d.lkvmCommand(c, "stop")
	return err
}

func (d *driver) containerDir(containerID string) string {
	return path.Join(d.libPath, "containers", containerID)
}

// isDigit returns true if s can be represented as an integer
func isDigit(s string) bool {
	if _, err := strconv.Atoi(s); err == nil {
		return true
	}

	return false
}

func (d *driver) getInfo(id string) ([]byte, error) {
	output, err := d.lkvmCommand(nil, "list")
	if err != nil {
		return nil, err
	}

	for i, line := range strings.Split(string(output), "\n") {
		if i < 2 {
			continue
		}

		fields := strings.Fields(strings.TrimSpace(line))

		if len(fields) != 3 {
			continue
		}

		if !isDigit(fields[0]) {
			continue
		}

		if fields[1] != id {
			continue
		}

		return []byte(line), nil
	}

	return []byte(fmt.Sprintf("-1 %s stopped", id)), nil
}

type info struct {
	ID     string
	driver *driver
}

func (i *info) IsRunning() bool {
	output, err := i.driver.getInfo(i.ID)
	if err != nil {
		logrus.Errorf("Error getting info for %s container %s: %s (%s)",
			driverName, i.ID, err, output)
		return false
	}

	clrInfo, err := parseClrInfo(i.ID, string(output))

	if err != nil {
		return false
	}

	return clrInfo.Running
}

func (d *driver) Info(id string) execdriver.Info {
	return &info{
		ID:     id,
		driver: d,
	}
}

func (d *driver) GetPidsForContainer(id string) ([]int, error) {
	// The VM doesn't expose the worload pid(s), so the only meaningful
	// pid is that of the VM
	return []int{d.containerPid}, nil
}

// TtyConsole is a type to represent a pseud-oterminal (see pty(7))
type TtyConsole struct {
	MasterPty *os.File
	SlavePty  *os.File
}

// NewTtyConsole returns a new TtyConsole object.
func NewTtyConsole(processConfig *execdriver.ProcessConfig, pipes *execdriver.Pipes) (*TtyConsole, error) {
	// lxc is special in that we cannot create the master outside of the container without
	// opening the slave because we have nothing to provide to the cmd.  We have to open both then do
	// the crazy setup on command right now instead of passing the console path to lxc and telling it
	// to open up that console.  we save a couple of openfiles in the native driver because we can do
	// this.
	ptyMaster, ptySlave, err := pty.Open()
	if err != nil {
		return nil, err
	}

	tty := &TtyConsole{
		MasterPty: ptyMaster,
		SlavePty:  ptySlave,
	}

	if err := tty.AttachPipes(&processConfig.Cmd, pipes); err != nil {
		tty.Close()
		return nil, err
	}

	processConfig.Console = tty.SlavePty.Name()

	return tty, nil
}

// Master returns the master end of the pty
func (t *TtyConsole) Master() *os.File {
	return t.MasterPty
}

// Resize modifies the size of the pty terminal being used.
func (t *TtyConsole) Resize(h, w int) error {
	return term.SetWinsize(t.MasterPty.Fd(), &term.Winsize{Height: uint16(h), Width: uint16(w)})
}

// AttachPipes associates the specified pipes with the pty master.
func (t *TtyConsole) AttachPipes(command *exec.Cmd, pipes *execdriver.Pipes) error {
	command.Stdout = t.SlavePty
	command.Stderr = t.SlavePty

	go func() {
		if wb, ok := pipes.Stdout.(interface {
			CloseWriters() error
		}); ok {
			defer wb.CloseWriters()
		}

		io.Copy(pipes.Stdout, t.MasterPty)
	}()

	if pipes.Stdin != nil {
		command.Stdin = t.SlavePty
		command.SysProcAttr.Setctty = true

		go func() {
			io.Copy(t.MasterPty, pipes.Stdin)

			pipes.Stdin.Close()
		}()
	}
	return nil
}

// Close closes both ends of the pty.
func (t *TtyConsole) Close() error {
	t.SlavePty.Close()
	return t.MasterPty.Close()
}

func (d *driver) Exec(c *execdriver.Command, processConfig *execdriver.ProcessConfig, pipes *execdriver.Pipes, hooks execdriver.Hooks) (int, error) {
	return -1, fmt.Errorf("Unsupported: Exec is not supported by the %q driver", driverName)

}

// Clean up after an Exec
func (d *driver) Clean(id string) error {
	return nil
}

func (d *driver) generateEnvConfig(c *execdriver.Command) error {
	data := []byte(strings.Join(c.ProcessConfig.Env, "\n"))

	p := path.Join(d.libPath, "containers", c.ID, "config.env")
	c.Mounts = append(c.Mounts, execdriver.Mount{
		Source:      p,
		Destination: "/.dockerenv",
		Writable:    false,
		Private:     true,
	})

	return ioutil.WriteFile(p, data, 0600)
}

func (d *driver) generateDockerInit(c *execdriver.Command) error {
	p := fmt.Sprintf("%s/.containerexec", c.Rootfs)
	var args []string

	if pathExecutable(p) {
		return nil
	}

	args = append(args, c.ProcessConfig.Entrypoint)
	args = append(args, c.ProcessConfig.Arguments...)

	data := []byte(fmt.Sprintf("#!/bin/sh\n%s\n", strings.Join(args, " ")))

	return ioutil.WriteFile(p, data, 0755)
}

func (d *driver) linkExists(name string) bool {
	cmd := exec.Command("ip", "link", "show", name)
	err := cmd.Run()

	return err == nil
}

func (d *driver) setupNetwork(c *execdriver.Command) error {
	ifname := getTapIf(c)

	var bridgeName string
	var bridgeLinkName string
	var output []byte
	var err error
	var ok bool

	bridge := c.NetworkSettings.Networks["bridge"]
	if bridge == nil {
		return fmt.Errorf("no bridge network available")
	}

	d.ipaddr = bridge.IPAddress
	d.macaddr = bridge.MacAddress
	d.gateway = bridge.Gateway

	// Extract the bridge details from the relevant endpoint.
	for _, info := range c.EndpointInfo {
		if _, ok = info[netlabel.BridgeEID].(string); !ok {
			continue
		}

		if bridgeName, ok = info[netlabel.BridgeName].(string); !ok {
			return fmt.Errorf("unable to determine bridge name")
		}

		if bridgeLinkName, ok = info[netlabel.BridgeLinkName].(string); !ok {
			return fmt.Errorf("unable to determine bridge link name")
		}
	}

	// Strip existing veth if it exists
	if bridgeLinkName != "" && d.linkExists(bridgeLinkName) {
		cmd := exec.Command("ip", "link", "del", bridgeLinkName)
		if output, err = cmd.CombinedOutput(); err != nil {
			logrus.Debugf("%s setupNetwork error: %v, %s", driverName, cmd.Args, output)
			return err
		}
	}

	cmd := exec.Command("ip", "tuntap", "add", "dev", ifname, "mode", "tap", "vnet_hdr")
	if output, err = cmd.CombinedOutput(); err != nil {
		logrus.Debugf("%s setupNetwork error: %v, %s", driverName, cmd.Args, output)
		return err
	}
	cmd = exec.Command("ip", "link", "set", "dev", ifname, "master", bridgeName)
	if output, err = cmd.CombinedOutput(); err != nil {
		logrus.Debugf("%s setupNetwork error: %v, %s", driverName, cmd.Args, output)
		return err
	}

	cmd = exec.Command("ip", "link", "set", "dev", ifname, "up")
	if output, err = cmd.CombinedOutput(); err != nil {
		logrus.Debugf("%s setupNetwork error: %v, %s", driverName, cmd.Args, output)
		return err
	}

	return err
}

func (d *driver) Stats(id string) (*execdriver.ResourceStats, error) {
	if _, ok := d.activeContainers[id]; !ok {
		return nil, fmt.Errorf("%s is not a key in active containers", id)
	}
	// FIXME:
	return execdriver.Stats(d.containerDir(id), d.activeContainers[id].container.Cgroups.Memory, d.machineMemory)
}

func (d *driver) SupportsHooks() bool {
	return false
}
