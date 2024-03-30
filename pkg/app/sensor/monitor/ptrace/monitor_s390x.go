//go:build linux
// +build linux

package ptrace

import (
	"context"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"syscall"

	log "github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"

	"github.com/slimtoolkit/slim/pkg/errors"
	"github.com/slimtoolkit/slim/pkg/launcher"
	"github.com/slimtoolkit/slim/pkg/mondel"
	"github.com/slimtoolkit/slim/pkg/report"
	"github.com/slimtoolkit/slim/pkg/system"
)

type syscallEvent struct {
	callNum uint32
	retVal  uint64
}

const (
	eventBufSize = 500
	ptOptions    = unix.PTRACE_O_TRACESYSGOOD | // flag syscall-stops with SIGTRAP|0x80 signal
		unix.PTRACE_O_EXITKILL |
		unix.PTRACE_O_TRACECLONE |
		unix.PTRACE_O_TRACEFORK |
		unix.PTRACE_O_TRACEVFORK |
		unix.PTRACE_O_TRACEEXIT

	traceSysGoodStatusBit = 0x80
)

type status struct {
	report *report.PtMonitorReport
	err    error
}

type monitor struct {
	ctx    context.Context
	cancel context.CancelFunc

	del mondel.Publisher

	artifactsDir string

	runOpt AppRunOpt

	// TODO: Move the logic behind these two fields to the artifact processig stage.
	includeNew bool
	origPaths  map[string]struct{}

	// To receive signals that should be delivered to the target app.
	signalCh <-chan os.Signal

	status status
	doneCh chan struct{}
}

func NewMonitor(
	ctx context.Context,
	del mondel.Publisher,
	artifactsDir string,
	runOpt AppRunOpt,
	includeNew bool,
	origPaths map[string]struct{},
	signalCh <-chan os.Signal,
	errorCh chan<- error,
) Monitor {
	ctx, cancel := context.WithCancel(ctx)
	return &monitor{
		ctx:    ctx,
		cancel: cancel,

		del: del,

		artifactsDir: artifactsDir,

		runOpt: runOpt,

		includeNew: includeNew,
		origPaths:  origPaths,

		signalCh: signalCh,

		doneCh: make(chan struct{}),
	}
}

func (m *monitor) Start() error {
	logger := log.WithField("op", "sensor.pt.monitor.Start")
	logger.Info("call")
	defer logger.Info("exit")

	logger.WithFields(log.Fields{
		"name": m.runOpt.Cmd,
		"args": m.runOpt.Args,
	}).Debug("starting target app...")

	sysInfo := system.GetSystemInfo()
	archName := system.MachineToArchName(sysInfo.Machine)
	syscallResolver := system.CallNumberResolver(archName)

	appName := m.runOpt.Cmd
	appArgs := m.runOpt.Args
	workDir := m.runOpt.WorkDir
	appUser := m.runOpt.User
	runTargetAsUser := m.runOpt.RunAsUser
	rtaSourcePT := m.runOpt.RTASourcePT
	// TODO(ivan): Implement the runOpt.ReportOnMainPidExit handling.

	// The sync part of the start was successful.

	// Starting the async part...
	go func() {
		logger := log.WithField("op", "sensor.pt.monitor.processor")
		logger.Debug("call")
		defer logger.Debug("exit")

		ptReport := &report.PtMonitorReport{
			ArchName:     string(archName),
			SyscallStats: map[string]report.SyscallStatInfo{},
		}

		syscallStats := map[uint32]uint64{}
		eventChan := make(chan syscallEvent, eventBufSize)
		collectorDoneChan := make(chan int, 1)

		var app *exec.Cmd

		go func() {
			logger := log.WithField("op", "sensor.pt.monitor.collector")
			logger.Debug("call")
			defer logger.Debug("exit")

			//IMPORTANT:
			//Ptrace is not pretty... and it requires that you do all ptrace calls from the same thread
			runtime.LockOSThread()

			var err error
			app, err = launcher.Start(
				appName,
				appArgs,
				workDir,
				appUser,
				runTargetAsUser,
				rtaSourcePT,
				m.runOpt.AppStdout,
				m.runOpt.AppStderr,
			)
			if err != nil {
				m.status.err = errors.SE("sensor.ptrace.Run/launcher.Start", "call.error", err)
				close(m.doneCh)
				return
			}

			// TODO: Apparently, rtaSourcePT is ignored by this below code.
			//       The x86-64 version of it has an alternative code branch
			//       to run the target app w/o tracing.

			cancelSignalForwarding := startSignalForwarding(m.ctx, app, m.signalCh)
			defer cancelSignalForwarding()

			targetPid := app.Process.Pid

			//pgid, err := syscall.Getpgid(targetPid)
			//if err != nil {
			//	log.Warnf("ptmon: collector - getpgid error %d: %v", targetPid, err)
			//	collectorDoneChan <- 1
			//	return
			//}

			logger.Debugf("target PID ==> %d", targetPid)

			var wstat unix.WaitStatus

			//pid, err := syscall.Wait4(-1, &wstat, syscall.WALL, nil) - WIP
			pid, err := unix.Wait4(targetPid, &wstat, 0, nil)
			if err != nil {
				logger.Warnf("unix.Wait4 - error waiting for %d: %v", targetPid, err)
				collectorDoneChan <- 2
				return
			}
			if pid != targetPid {
				logger.Tracef("wait4 returned new pid(%d), expected(%d)", pid, targetPid)
			}

			err = syscall.PtraceSetOptions(targetPid, ptOptions)
			if err != nil {
				log.Warnf("ptmon: collector - error setting trace options %d: %v", targetPid, err)
				collectorDoneChan <- 3
				return
			}

			logger.Debugf("initial process status = %v (pid=%d)", wstat, pid)

			if wstat.Exited() {
				logger.Warn("app exited (unexpected)")
				collectorDoneChan <- 4
				return
			}

			if wstat.Signaled() {
				logger.Warn("app signalled (unexpected)")
				collectorDoneChan <- 5
				return
			}

			syscallReturn := false
			gotCallNum := false
			gotRetVal := false
			var callNum uint64
			var retVal uint64
			for wstat.Stopped() {

				stopSig := wstat.StopSignal()

				var stopType = "syscall_stop"
				if stopSig != unix.SIGTRAP|traceSysGoodStatusBit {

					switch wstat.TrapCause() {
					case syscall.PTRACE_EVENT_CLONE,
						syscall.PTRACE_EVENT_FORK,
						syscall.PTRACE_EVENT_VFORK,
						syscall.PTRACE_EVENT_VFORK_DONE,
						syscall.PTRACE_EVENT_EXEC,
						syscall.PTRACE_EVENT_EXIT:
						stopType = "ptrace_event_stop"
					case syscall.PTRACE_EVENT_SECCOMP:
						stopType = "seccomp_stop"
					default:
						switch stopSig {
						case syscall.SIGSTOP,
							syscall.SIGTSTP,
							syscall.SIGTTIN,
							syscall.SIGTTOU:
							stopType = "group_stop"
						default:
							if stopSig == unix.SIGTRAP {
								stopType = "ptrace_stop"

							} else {
								stopType = "signal_stop"
							}
						}
					}
				}

				logger.Tracef("stopSig=%d (%s), stop type => %v", int(stopSig), stopSig.String(), stopType)
				var childSig = int(0)
				if stopType != "syscall_stop" {

					if stopType == "signal_stop" {
						childSig = int(stopSig)
					}
					logger.Tracef("non syscall stop, returning control to pid (%d), sig(%d)...", pid, childSig)
				} else {
					var regs unix.PtraceRegs

					if err := unix.PtraceGetRegs(targetPid, &regs); err != nil {
						//if err := syscall.PtraceGetRegs(pid, &regs); err != nil {
						logger.Fatalf("unix.PtraceGetRegs(call): %v", err)
					}

					switch syscallReturn {
					case false:
						logger.Tracef("before syscall: orig_r2=%d, r0=%d, r1=%d, r2=%d ", regs.Orig_gpr2, regs.Gprs[0], regs.Gprs[1], regs.Gprs[2])

						callNum = system.CallNumber(regs)
						syscallReturn = true
						gotCallNum = true

					case true:
						logger.Tracef("after syscall: orig_r2=%d, r0=%d, r1=%d, r2=%d ", regs.Orig_gpr2, regs.Gprs[0], regs.Gprs[1], regs.Gprs[2])

						retVal = system.CallReturnValue(regs)
						syscallReturn = false
						gotRetVal = true

					}

				}

				//err = syscall.PtraceSyscall(pid, 0)
				// continue execution
				err = unix.PtraceSyscall(pid, childSig)
				if err != nil {
					logger.Warnf("unix.PtraceSyscall error: %v", err)
					break
				}

				//pid, err = syscall.Wait4(-1, &wstat, syscall.WALL, nil)
				pid, err = unix.Wait4(pid, &wstat, 0, nil)
				if err != nil {
					logger.Warnf("unix.Wait4 - error waiting 4 %d: %v", pid, err)
					break
				}
				if pid != targetPid {
					logger.Tracef("wait4 returned new pid(%d), expected(%d)", pid, targetPid)
				}

				if gotCallNum && gotRetVal {
					gotCallNum = false
					gotRetVal = false

					select {
					case eventChan <- syscallEvent{
						callNum: uint32(callNum),
						retVal:  retVal,
					}:
					case <-m.ctx.Done():
						logger.Info("stopping...")
						return
					}
				}
			}

			logger.Infof("exiting... status=%v", wstat)
			collectorDoneChan <- 0
		}()

	done:
		for {
			select {
			case rc := <-collectorDoneChan:
				logger.Info("collector finished =>", rc)
				break done
			case <-m.ctx.Done():
				logger.Info("stopping...")
				//NOTE: need a better way to stop the target app...
				if err := app.Process.Signal(unix.SIGTERM); err != nil {
					logger.Warnf("app.Process.Signal(unix.SIGTERM) - error stopping target app => %v", err)
					if err := app.Process.Kill(); err != nil {
						logger.Warnf("app.Process.Kill - error killing target app => %v", *app)
					}
				}
				break done
			case e := <-eventChan:
				ptReport.SyscallCount++
				logger.Tracef("syscall ==> %d (%s)", e.callNum, syscallResolver(e.callNum))

				if _, ok := syscallStats[e.callNum]; ok {
					syscallStats[e.callNum]++
				} else {
					syscallStats[e.callNum] = 1
				}
			}
		}

		logger.Debugf("executed syscall count = %d", ptReport.SyscallCount)
		logger.Debugf("number of syscalls: %v", len(syscallStats))
		for scNum, scCount := range syscallStats {
			logger.Tracef("%v", syscallResolver(scNum))
			logger.Tracef("[%v] %v = %v", scNum, syscallResolver(scNum), scCount)
			ptReport.SyscallStats[strconv.FormatInt(int64(scNum), 10)] = report.SyscallStatInfo{
				Number: scNum,
				Name:   syscallResolver(scNum),
				Count:  scCount,
			}
		}

		ptReport.SyscallNum = uint32(len(ptReport.SyscallStats))

		m.status.report = ptReport
		close(m.doneCh)
	}()

	return nil
}

func (m *monitor) Cancel() {
	m.cancel()
}

func (m *monitor) Done() <-chan struct{} {
	return m.doneCh
}

func (m *monitor) Status() (*report.PtMonitorReport, error) {
	return m.status.report, m.status.err
}

func startSignalForwarding(
	ctx context.Context,
	app *exec.Cmd,
	signalCh <-chan os.Signal,
) context.CancelFunc {
	log.Debug("ptmon: signal forwarder - starting...")

	ctx, cancel := context.WithCancel(ctx)

	go func() {
		for {
			select {
			case <-ctx.Done():
				return

			case s := <-signalCh:
				log.WithField("signal", s).Debug("ptmon: signal forwarder - received signal")

				if s == syscall.SIGCHLD {
					continue
				}

				log.WithField("signal", s).Debug("ptmon: signal forwarder - forwarding signal")

				if err := app.Process.Signal(s); err != nil {
					log.
						WithError(err).
						WithField("signal", s).
						Debug("ptmon: signal forwarder - failed to signal target app")
				}
			}
		}
	}()

	return cancel
}
